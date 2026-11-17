"""Orchestrate refang -> detect -> source lookups -> scoring."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from ioc_enrich.cache import Cache
from ioc_enrich.detect import IOCType, detect
from ioc_enrich.refang import refang
from ioc_enrich.scoring import EnrichmentResult, score
from ioc_enrich.sources.base import Source, SourceResult, Status


class Enricher:
    """Enrich IOCs using a set of configured sources and an optional cache.

    IOCs are only ever sent to the sources passed in here.
    """

    def __init__(
        self,
        sources: Sequence[Source],
        skipped: Iterable[str] = (),
        cache: Cache | None = None,
    ) -> None:
        self.sources = list(sources)
        self.skipped = list(skipped)
        self.cache = cache

    def enrich(self, raw: str) -> EnrichmentResult:
        """Enrich a single (possibly defanged) IOC."""
        ioc = refang(raw)
        ioc_type = detect(ioc)
        if ioc_type is IOCType.DOMAIN:
            ioc = ioc.rstrip(".").lower()
        elif ioc_type.is_hash:
            ioc = ioc.lower()

        results: list[SourceResult] = []
        if ioc_type is not IOCType.UNKNOWN:
            for src in self.sources:
                results.append(self._lookup(src, ioc, ioc_type))
            results.extend(
                SourceResult(name, Status.SKIPPED, summary="no API key") for name in self.skipped
            )
        return EnrichmentResult(ioc, raw.strip(), ioc_type, results, score(results))

    def enrich_many(self, raws: Iterable[str]) -> list[EnrichmentResult]:
        """Enrich several IOCs, de-duplicating after refanging."""
        seen: set[str] = set()
        out: list[EnrichmentResult] = []
        for raw in raws:
            key = refang(raw).lower()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(self.enrich(raw))
        return out

    def _lookup(self, src: Source, ioc: str, ioc_type: IOCType) -> SourceResult:
        if not src.supports(ioc_type):
            return SourceResult(src.name, Status.UNSUPPORTED)
        if self.cache is not None:
            cached = self.cache.get(src.name, ioc)
            if cached is not None:
                return cached
        res = src.lookup(ioc, ioc_type)
        if self.cache is not None and res.status in (Status.FOUND, Status.NOT_FOUND):
            self.cache.set(src.name, ioc, res)
        return res

    def close(self) -> None:
        """Release HTTP clients and the cache."""
        for s in self.sources:
            s.close()
        if self.cache is not None:
            self.cache.close()
