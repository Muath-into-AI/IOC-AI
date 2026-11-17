import httpx
import pytest


@pytest.fixture
def client():
    """Plain httpx client; respx intercepts its requests."""
    with httpx.Client(timeout=5) as c:
        yield c


@pytest.fixture
def no_sleep():
    """Record sleeps instead of actually sleeping."""
    calls: list[float] = []
    return calls.append, calls


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, tmp_path):
    """Never use real keys or the user's cache during tests."""
    for var in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY", "OTX_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("IOC_ENRICH_CACHE", str(tmp_path / "cache.sqlite"))
    monkeypatch.chdir(tmp_path)
