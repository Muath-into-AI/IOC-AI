from ioc_enrich.scoring import level_for, score
from ioc_enrich.sources.base import SourceResult, Status


def r(source: str, data: dict, status: Status = Status.FOUND) -> SourceResult:
    return SourceResult(source, status, data=data)


def test_unknown_when_no_data() -> None:
    s = score([SourceResult("virustotal", Status.SKIPPED), SourceResult("otx", Status.ERROR)])
    assert s.value == 0
    assert s.level == "unknown"


def test_clean() -> None:
    s = score([r("virustotal", {"malicious": 0, "harmless": 70}, Status.FOUND)])
    assert s.value == 0
    assert s.level == "none"
    assert s.reasons == ["no source reported malicious activity"]


def test_virustotal_tiers_and_cap() -> None:
    assert score([r("virustotal", {"malicious": 1})]).value == 15
    assert score([r("virustotal", {"malicious": 5})]).value == 35
    assert score([r("virustotal", {"malicious": 60, "suspicious": 3})]).value == 50


def test_abuseipdb_and_whitelist() -> None:
    assert score([r("abuseipdb", {"abuse_confidence": 100, "total_reports": 9})]).value == 40
    s = score([r("abuseipdb", {"abuse_confidence": 0, "is_whitelisted": True})])
    assert s.value == 0
    assert "AbuseIPDB: IP is whitelisted" in s.reasons


def test_combined_is_clamped() -> None:
    s = score(
        [
            r("virustotal", {"malicious": 60}),
            r("malwarebazaar", {"listed": True, "signature": "Emotet"}),
            r("urlhaus", {"listed": True, "url_status": "online"}),
            r("otx", {"pulse_count": 30}),
        ]
    )
    assert s.value == 100
    assert s.level == "critical"
    assert any("Emotet" in x for x in s.reasons)


def test_otx_tiers() -> None:
    assert score([r("otx", {"pulse_count": 1})]).value == 5
    assert score([r("otx", {"pulse_count": 4})]).value == 12
    assert score([r("otx", {"pulse_count": 10})]).value == 20


def test_levels() -> None:
    assert level_for(0) == "none"
    assert level_for(10) == "low"
    assert level_for(30) == "medium"
    assert level_for(60) == "high"
    assert level_for(95) == "critical"
