"""abuse.ch URLhaus source (URLs, hosts, and payload hashes).

``data`` keys: ``listed`` (bool), and depending on type ``url_status``
(online/offline), ``threat``, ``tags``, ``url_count``, ``signature``.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ioc_enrich.detect import IOCType
from ioc_enrich.sources.base import Source, SourceError, SourceResult, Status

BASE_URL = "https://urlhaus-api.abuse.ch/v1"


class URLhaus(Source):
    """Lookups against the URLhaus API."""

    name = "urlhaus"
    env_key = "ABUSECH_AUTH_KEY"
    supported_types = frozenset(
        {
            IOCType.URL,
            IOCType.DOMAIN,
            IOCType.IPV4,
            IOCType.IPV6,
            IOCType.MD5,
            IOCType.SHA256,
        }
    )
    rate_limit_per_minute = 60.0

    def _payload(self, ioc: str, ioc_type: IOCType) -> tuple[str, dict[str, str]]:
        if ioc_type is IOCType.URL:
            return f"{BASE_URL}/url/", {"url": ioc}
        if ioc_type is IOCType.MD5:
            return f"{BASE_URL}/payload/", {"md5_hash": ioc}
        if ioc_type is IOCType.SHA256:
            return f"{BASE_URL}/payload/", {"sha256_hash": ioc}
        return f"{BASE_URL}/host/", {"host": ioc}

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        url, form = self._payload(ioc, ioc_type)
        resp = self.request("POST", url, data=form, headers={"Auth-Key": self.api_key})
        if resp.status_code in (401, 403):
            raise SourceError(f"authentication failed (HTTP {resp.status_code})")
        resp.raise_for_status()
        body = resp.json()
        status = body.get("query_status")
        if status in ("no_results", "not_found"):
            return SourceResult(
                self.name, Status.NOT_FOUND, data={"listed": False}, summary="not listed"
            )
        if status != "ok":
            raise SourceError(f"query_status={status}")

        data: dict[str, object] = {"listed": True}
        if ioc_type is IOCType.URL:
            data.update(
                url_status=body.get("url_status"),
                threat=body.get("threat"),
                tags=body.get("tags") or [],
                host=urlsplit(ioc).hostname,
            )
            summary = f"listed ({body.get('threat') or 'malware'}, {body.get('url_status')})"
        elif ioc_type.is_hash:
            data.update(
                signature=body.get("signature"),
                file_type=body.get("file_type"),
                url_count=int(body.get("url_count") or 0),
            )
            summary = f"payload seen on {data['url_count']} URLs"
            if data["signature"]:
                summary += f" ({data['signature']})"
        else:
            urls = body.get("urls") or []
            online = sum(1 for u in urls if u.get("url_status") == "online")
            data.update(url_count=int(body.get("url_count") or len(urls)), online=online)
            summary = f"host has {data['url_count']} malicious URLs ({online} online)"
        return SourceResult(self.name, Status.FOUND, data=data, summary=summary)
