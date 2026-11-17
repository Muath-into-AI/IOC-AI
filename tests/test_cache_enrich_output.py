import csv
import io
import json

import respx

from ioc_enrich import cli
from ioc_enrich.cache import Cache
from ioc_enrich.detect import IOCType
from ioc_enrich.enrich import Enricher
from ioc_enrich.output import render_csv, render_json, render_markdown, render_table
from ioc_enrich.sources import VirusTotal
from ioc_enrich.sources.base import SourceResult, Status

EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
VT_FILE = f"https://www.virustotal.com/api/v3/files/{EICAR_MD5}"
VT_BODY = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 62,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 8,
            }
        }
    }
}


# ---------------------------------------------------------------- cache
def test_cache_roundtrip_and_ttl():
    now = [1000.0]
    c = Cache(":memory:", ttl=60, clock=lambda: now[0])
    res = SourceResult("otx", Status.FOUND, data={"pulse_count": 3}, summary="3 pulses")
    c.set("otx", "example.com", res)
    assert c.get("otx", "example.com") == res
    now[0] += 61
    assert c.get("otx", "example.com") is None
    c.close()


def test_cache_purge(tmp_path):
    now = [0.0]
    c = Cache(tmp_path / "sub" / "c.sqlite", ttl=10, clock=lambda: now[0])
    c.set("a", "x", SourceResult("a", Status.NOT_FOUND))
    now[0] = 20
    assert c.purge_expired() == 1
    c.close()


# ---------------------------------------------------------------- enricher
@respx.mock
def test_enricher_uses_cache_and_refangs():
    route = respx.get(VT_FILE).respond(json=VT_BODY)
    vt = VirusTotal("k", sleep=lambda _: None)
    cache = Cache(":memory:")
    e = Enricher([vt], skipped=["abuseipdb", "malwarebazaar"], cache=cache)

    first = e.enrich(EICAR_MD5.upper())
    second = e.enrich(EICAR_MD5)
    assert route.call_count == 1  # second lookup served from cache
    assert first.ioc == EICAR_MD5
    assert first.ioc_type is IOCType.MD5
    assert first.score.value == 50
    # abuseipdb doesn't handle hashes, so it isn't listed as skipped
    assert [r.source for r in second.results] == ["virustotal", "malwarebazaar"]
    e.close()


def test_enricher_unknown_and_dedup():
    e = Enricher([], skipped=["virustotal"])
    results = e.enrich_many(["hxxp://example[.]com", "http://example.com", "???", ""])
    assert [r.ioc for r in results] == ["http://example.com", "???"]
    assert results[0].original == "hxxp://example[.]com"
    assert results[1].ioc_type is IOCType.UNKNOWN
    assert results[1].results == []


# ---------------------------------------------------------------- output
def _sample():
    return Enricher([], skipped=["virustotal"]).enrich_many(["8.8.8.8", "hxxp://a|b[.]com"])


def test_json_output():
    data = json.loads(render_json(_sample()))
    assert data[0]["type"] == "ipv4"
    assert data[0]["level"] == "unknown"
    assert data[0]["sources"][0]["status"] == "skipped"


def test_csv_output():
    rows = list(csv.DictReader(io.StringIO(render_csv(_sample()))))
    assert rows[0]["ioc"] == "8.8.8.8"
    assert rows[0]["score"] == "0"


def test_markdown_output_escapes_pipes():
    md = render_markdown(_sample())
    assert md.startswith("# IOC enrichment report")
    assert "| `8.8.8.8` | ipv4 | 0 | unknown |" in md
    assert "a\\|b" in md


def test_table_output():
    from rich.console import Console

    buf = io.StringIO()
    render_table(_sample(), Console(file=buf, width=200, color_system=None))
    out = buf.getvalue()
    assert "8.8.8.8" in out
    assert "virustotal: no API key" in out


# ---------------------------------------------------------------- cli
def test_cli_no_input(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    assert cli.main([]) == 2
    assert "no IOCs" in capsys.readouterr().err


@respx.mock
def test_cli_json_with_key(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "k")
    respx.get(VT_FILE).respond(json=VT_BODY)
    f = tmp_path / "iocs.txt"
    f.write_text(f"# comment\n{EICAR_MD5}\n\n")
    assert cli.main(["-f", str(f), "--json", "--no-cache", "--sources", "virustotal"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["score"] == 50
    assert data[0]["level"] == "medium"


def test_cli_md_to_file(tmp_path):
    out = tmp_path / "report.md"
    assert cli.main(["8.8.8.8", "--md", "-o", str(out)]) == 0
    assert "# IOC enrichment report" in out.read_text()


def test_cli_stdin(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("8.8.8.8\nexample[.]com\n"))
    assert cli.main(["--csv"]) == 0
    out = capsys.readouterr().out
    assert "example.com" in out
    assert "8.8.8.8" in out
