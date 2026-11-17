"""AbuseIPDB v2 source (IP addresses only).

``data`` keys: ``abuse_confidence`` (0-100), ``total_reports``,
``country``, ``isp``, ``usage_type``, ``is_whitelisted``.
"""

from __future__ import annotations

from ioc_enrich.detect import IOCType
from ioc_enrich.sources.base import Source, SourceError, SourceResult, Status

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDB(Source):
    """Lookups against AbuseIPDB (free tier: 1,000 checks/day)."""

    name = "abuseipdb"
    env_key = "ABUSEIPDB_API_KEY"
    supported_types = frozenset({IOCType.IPV4, IOCType.IPV6})
    rate_limit_per_minute = 30.0

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        resp = self.request(
            "GET",
            CHECK_URL,
            params={"ipAddress": ioc, "maxAgeInDays": 90},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        if resp.status_code in (401, 403):
            raise SourceError(f"authentication failed (HTTP {resp.status_code})")
        resp.raise_for_status()

        d = resp.json()["data"]
        data = {
            "abuse_confidence": int(d.get("abuseConfidenceScore") or 0),
            "total_reports": int(d.get("totalReports") or 0),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "usage_type": d.get("usageType"),
            "is_whitelisted": bool(d.get("isWhitelisted")),
        }
        if data["total_reports"] == 0:
            return SourceResult(self.name, Status.NOT_FOUND, data=data, summary="no abuse reports")
        summary = f"confidence {data['abuse_confidence']}%, {data['total_reports']} reports"
        return SourceResult(self.name, Status.FOUND, data=data, summary=summary)
