"""Threat-intel sources. Each source is skipped if its API key is not configured."""

from __future__ import annotations

import os
from collections.abc import Mapping

from ioc_enrich.sources.abuseipdb import AbuseIPDB
from ioc_enrich.sources.base import Source, SourceResult, Status
from ioc_enrich.sources.malwarebazaar import MalwareBazaar
from ioc_enrich.sources.otx import OTX
from ioc_enrich.sources.urlhaus import URLhaus
from ioc_enrich.sources.virustotal import VirusTotal

ALL_SOURCES: tuple[type[Source], ...] = (VirusTotal, AbuseIPDB, URLhaus, MalwareBazaar, OTX)

__all__ = [
    "ALL_SOURCES",
    "OTX",
    "AbuseIPDB",
    "MalwareBazaar",
    "Source",
    "SourceResult",
    "Status",
    "URLhaus",
    "VirusTotal",
    "build_sources",
]


def build_sources(
    env: Mapping[str, str] | None = None,
    only: set[str] | None = None,
    timeout: float = 15.0,
) -> tuple[list[Source], list[str]]:
    """Instantiate every source whose API key is present.

    Returns ``(enabled_sources, skipped_source_names)``.
    """
    env = os.environ if env is None else env
    enabled: list[Source] = []
    skipped: list[str] = []
    for cls in ALL_SOURCES:
        if only and cls.name not in only:
            continue
        key = (env.get(cls.env_key) or "").strip()
        if key:
            enabled.append(cls(key, timeout=timeout))
        else:
            skipped.append(cls.name)
    return enabled, skipped
