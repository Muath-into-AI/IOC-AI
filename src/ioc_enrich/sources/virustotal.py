"""VirusTotal v3 source.

``data`` keys: ``malicious``, ``suspicious``, ``harmless``, ``undetected``
(engine counts from ``last_analysis_stats``), ``reputation``, and for files
``meaningful_name`` / ``type_description`` when available.
"""

from __future__ import annotations

import base64

from ioc_enrich.detect import IOCType
from ioc_enrich.sources.base import Source, SourceError, SourceResult, Status

BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotal(Source):
    """Lookups against the VirusTotal public API (free tier: 4 req/min)."""

    name = "virustotal"
    env_key = "VT_API_KEY"
    supported_types = frozenset(
        {
            IOCType.MD5,
            IOCType.SHA1,
            IOCType.SHA256,
            IOCType.IPV4,
            IOCType.IPV6,
            IOCType.DOMAIN,
            IOCType.URL,
        }
    )
    rate_limit_per_minute = 4.0

    def _endpoint(self, ioc: str, ioc_type: IOCType) -> str:
        if ioc_type.is_hash:
            return f"{BASE_URL}/files/{ioc}"
        if ioc_type.is_ip:
            return f"{BASE_URL}/ip_addresses/{ioc}"
        if ioc_type is IOCType.DOMAIN:
            return f"{BASE_URL}/domains/{ioc}"
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        return f"{BASE_URL}/urls/{url_id}"

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        resp = self.request(
            "GET", self._endpoint(ioc, ioc_type), headers={"x-apikey": self.api_key}
        )
        if resp.status_code == 404:
            return SourceResult(self.name, Status.NOT_FOUND, summary="not in VirusTotal")
        if resp.status_code in (401, 403):
            raise SourceError(f"authentication failed (HTTP {resp.status_code})")
        resp.raise_for_status()

        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        data = {
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "reputation": attrs.get("reputation"),
        }
        for key in ("meaningful_name", "type_description"):
            if attrs.get(key):
                data[key] = attrs[key]
        total = sum(data[k] for k in ("malicious", "suspicious", "harmless", "undetected"))
        summary = f"{data['malicious']}/{total} engines malicious"
        if data["suspicious"]:
            summary += f", {data['suspicious']} suspicious"
        return SourceResult(self.name, Status.FOUND, data=data, summary=summary)
