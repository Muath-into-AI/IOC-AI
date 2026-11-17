"""AlienVault OTX source.

``data`` keys: ``pulse_count``, ``pulses`` (up to 5 pulse names),
``malware_families``.
"""

from __future__ import annotations

from urllib.parse import quote

from ioc_enrich.detect import IOCType
from ioc_enrich.sources.base import Source, SourceError, SourceResult, Status

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

_SECTIONS = {
    IOCType.IPV4: "IPv4",
    IOCType.IPV6: "IPv6",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.MD5: "file",
    IOCType.SHA1: "file",
    IOCType.SHA256: "file",
}


class OTX(Source):
    """Lookups against AlienVault OTX."""

    name = "otx"
    env_key = "OTX_API_KEY"
    supported_types = frozenset(_SECTIONS)
    rate_limit_per_minute = 60.0

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        section = _SECTIONS[ioc_type]
        url = f"{BASE_URL}/{section}/{quote(ioc, safe='')}/general"
        resp = self.request("GET", url, headers={"X-OTX-API-KEY": self.api_key})
        if resp.status_code == 404:
            return SourceResult(
                self.name, Status.NOT_FOUND, data={"pulse_count": 0}, summary="not in OTX"
            )
        if resp.status_code in (401, 403):
            raise SourceError(f"authentication failed (HTTP {resp.status_code})")
        resp.raise_for_status()

        info = resp.json().get("pulse_info") or {}
        pulses = info.get("pulses") or []
        count = int(info.get("count") or len(pulses))
        families = sorted(
            {
                f.get("display_name") or f.get("id")
                for p in pulses
                for f in (p.get("malware_families") or [])
                if isinstance(f, dict)
            }
            - {None}
        )
        data = {
            "pulse_count": count,
            "pulses": [p.get("name") for p in pulses[:5]],
            "malware_families": families,
        }
        if count == 0:
            return SourceResult(self.name, Status.NOT_FOUND, data=data, summary="0 pulses")
        return SourceResult(self.name, Status.FOUND, data=data, summary=f"{count} pulses")
