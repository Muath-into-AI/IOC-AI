import base64

import httpx
import pytest
import respx

from ioc_enrich.detect import IOCType
from ioc_enrich.sources import (
    OTX,
    AbuseIPDB,
    MalwareBazaar,
    URLhaus,
    VirusTotal,
    build_sources,
)
from ioc_enrich.sources.base import RateLimiter, Status

EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


def make(cls, client, no_sleep):
    sleep, _ = no_sleep
    return cls("test-key", client=client, sleep=sleep)


# ---------------------------------------------------------------- VirusTotal
@respx.mock
def test_virustotal_file_found(client, no_sleep):
    route = respx.get(f"https://www.virustotal.com/api/v3/files/{EICAR_MD5}").respond(
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 60,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 10,
                    },
                    "meaningful_name": "eicar.com",
                }
            }
        }
    )
    res = make(VirusTotal, client, no_sleep).lookup(EICAR_MD5, IOCType.MD5)
    assert res.status is Status.FOUND
    assert res.data["malicious"] == 60
    assert res.summary.startswith("60/70")
    assert route.calls.last.request.headers["x-apikey"] == "test-key"


@respx.mock
def test_virustotal_url_id_and_not_found(client, no_sleep):
    url = "http://example.com"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    respx.get(f"https://www.virustotal.com/api/v3/urls/{url_id}").respond(404)
    res = make(VirusTotal, client, no_sleep).lookup(url, IOCType.URL)
    assert res.status is Status.NOT_FOUND


@respx.mock
def test_virustotal_auth_error(client, no_sleep):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").respond(401)
    res = make(VirusTotal, client, no_sleep).lookup("8.8.8.8", IOCType.IPV4)
    assert res.status is Status.ERROR
    assert "authentication" in res.error


def test_virustotal_unsupported(client, no_sleep):
    res = make(VirusTotal, client, no_sleep).lookup("a@b.com", IOCType.EMAIL)
    assert res.status is Status.UNSUPPORTED


# ---------------------------------------------------------------- AbuseIPDB
@respx.mock
def test_abuseipdb_found(client, no_sleep):
    route = respx.get("https://api.abuseipdb.com/api/v2/check").respond(
        json={
            "data": {
                "abuseConfidenceScore": 87,
                "totalReports": 12,
                "countryCode": "XX",
                "isWhitelisted": False,
            }
        }
    )
    res = make(AbuseIPDB, client, no_sleep).lookup("192.0.2.1", IOCType.IPV4)
    assert res.status is Status.FOUND
    assert res.data["abuse_confidence"] == 87
    req = route.calls.last.request
    assert req.url.params["ipAddress"] == "192.0.2.1"
    assert req.headers["Key"] == "test-key"


@respx.mock
def test_abuseipdb_clean(client, no_sleep):
    respx.get("https://api.abuseipdb.com/api/v2/check").respond(
        json={"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": True}}
    )
    res = make(AbuseIPDB, client, no_sleep).lookup("8.8.8.8", IOCType.IPV4)
    assert res.status is Status.NOT_FOUND
    assert res.data["is_whitelisted"] is True


def test_abuseipdb_only_ips(client, no_sleep):
    src = make(AbuseIPDB, client, no_sleep)
    assert src.lookup("example.com", IOCType.DOMAIN).status is Status.UNSUPPORTED


# ---------------------------------------------------------------- URLhaus
@respx.mock
def test_urlhaus_url_listed(client, no_sleep):
    route = respx.post("https://urlhaus-api.abuse.ch/v1/url/").respond(
        json={
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["exe"],
        }
    )
    res = make(URLhaus, client, no_sleep).lookup("http://bad.example/x.exe", IOCType.URL)
    assert res.status is Status.FOUND
    assert res.data["url_status"] == "online"
    assert route.calls.last.request.headers["Auth-Key"] == "test-key"
    assert b"url=" in route.calls.last.request.content


@respx.mock
def test_urlhaus_host_and_no_results(client, no_sleep):
    respx.post("https://urlhaus-api.abuse.ch/v1/host/").respond(json={"query_status": "no_results"})
    res = make(URLhaus, client, no_sleep).lookup("example.com", IOCType.DOMAIN)
    assert res.status is Status.NOT_FOUND
    assert res.data == {"listed": False}


@respx.mock
def test_urlhaus_payload(client, no_sleep):
    respx.post("https://urlhaus-api.abuse.ch/v1/payload/").respond(
        json={"query_status": "ok", "signature": "Emotet", "url_count": "3"}
    )
    res = make(URLhaus, client, no_sleep).lookup(EICAR_MD5, IOCType.MD5)
    assert res.data["url_count"] == 3
    assert "Emotet" in res.summary


@respx.mock
def test_urlhaus_bad_status(client, no_sleep):
    respx.post("https://urlhaus-api.abuse.ch/v1/host/").respond(
        json={"query_status": "invalid_host"}
    )
    res = make(URLhaus, client, no_sleep).lookup("example.com", IOCType.DOMAIN)
    assert res.status is Status.ERROR


# ---------------------------------------------------------------- MalwareBazaar
@respx.mock
def test_malwarebazaar_found(client, no_sleep):
    route = respx.post("https://mb-api.abuse.ch/api/v1/").respond(
        json={
            "query_status": "ok",
            "data": [{"signature": "AgentTesla", "file_type": "exe", "tags": ["rat"]}],
        }
    )
    res = make(MalwareBazaar, client, no_sleep).lookup(EICAR_MD5, IOCType.MD5)
    assert res.status is Status.FOUND
    assert res.data["signature"] == "AgentTesla"
    assert b"query=get_info" in route.calls.last.request.content


@respx.mock
def test_malwarebazaar_not_found(client, no_sleep):
    respx.post("https://mb-api.abuse.ch/api/v1/").respond(json={"query_status": "hash_not_found"})
    res = make(MalwareBazaar, client, no_sleep).lookup(EICAR_MD5, IOCType.MD5)
    assert res.status is Status.NOT_FOUND


# ---------------------------------------------------------------- OTX
@respx.mock
def test_otx_found(client, no_sleep):
    route = respx.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/192.0.2.1/general"
    ).respond(
        json={
            "pulse_info": {
                "count": 4,
                "pulses": [
                    {"name": "p1", "malware_families": [{"display_name": "Mirai"}]},
                    {"name": "p2", "malware_families": []},
                ],
            }
        }
    )
    res = make(OTX, client, no_sleep).lookup("192.0.2.1", IOCType.IPV4)
    assert res.status is Status.FOUND
    assert res.data["pulse_count"] == 4
    assert res.data["malware_families"] == ["Mirai"]
    assert route.calls.last.request.headers["X-OTX-API-KEY"] == "test-key"


@respx.mock
def test_otx_url_is_quoted_and_zero_pulses(client, no_sleep):
    route = respx.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/url/").respond(
        json={"pulse_info": {"count": 0, "pulses": []}}
    )
    res = make(OTX, client, no_sleep).lookup("http://example.com/a?b=1", IOCType.URL)
    assert res.status is Status.NOT_FOUND
    assert "http%3A%2F%2Fexample.com" in str(route.calls.last.request.url)


# ---------------------------------------------------------------- retries / limits
@respx.mock
def test_retry_on_429_then_success(client, no_sleep):
    sleep, calls = no_sleep
    respx.get("https://otx.alienvault.com/api/v1/indicators/domain/example.com/general").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "2"}),
            httpx.Response(503),
            httpx.Response(200, json={"pulse_info": {"count": 1, "pulses": [{"name": "x"}]}}),
        ]
    )
    res = OTX("k", client=client, sleep=sleep).lookup("example.com", IOCType.DOMAIN)
    assert res.status is Status.FOUND
    # Retry-After=2 after the 429, then 1 * 2**1 backoff after the 503
    # (any other entries are rate-limiter spacing).
    assert calls.count(2.0) >= 2


@respx.mock
def test_retry_gives_up(client, no_sleep):
    sleep, _ = no_sleep
    route = respx.get(
        "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general"
    ).respond(500)
    res = OTX("k", client=client, sleep=sleep).lookup("example.com", IOCType.DOMAIN)
    assert res.status is Status.ERROR
    assert route.call_count == 4  # 1 + max_retries


@respx.mock
def test_transport_error_is_reported(client, no_sleep):
    sleep, _ = no_sleep
    respx.get(url__startswith="https://otx.alienvault.com/").mock(
        side_effect=httpx.ConnectTimeout("timed out")
    )
    res = OTX("k", client=client, sleep=sleep).lookup("example.com", IOCType.DOMAIN)
    assert res.status is Status.ERROR
    assert "ConnectTimeout" in res.error


def test_rate_limiter_spaces_calls():
    slept: list[float] = []
    t = [100.0]
    limiter = RateLimiter(4, sleep=slept.append, clock=lambda: t[0])
    limiter.wait()
    limiter.wait()
    assert slept == [pytest.approx(15.0)]


def test_build_sources_skips_missing_keys():
    enabled, skipped = build_sources({"VT_API_KEY": "x", "ABUSECH_AUTH_KEY": " "})
    assert [s.name for s in enabled] == ["virustotal"]
    assert set(skipped) == {"abuseipdb", "urlhaus", "malwarebazaar", "otx"}
    enabled, _ = build_sources({"VT_API_KEY": "x", "OTX_API_KEY": "y"}, only={"otx"})
    assert [s.name for s in enabled] == ["otx"]
