"""Common base class for threat-intel sources."""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar

import httpx

from ioc_enrich import __version__
from ioc_enrich.detect import IOCType

DEFAULT_TIMEOUT = 15.0
USER_AGENT = f"ioc-enrich/{__version__} (+defensive IOC triage)"


class Status(str, Enum):
    """Outcome of a single source lookup."""

    FOUND = "found"
    NOT_FOUND = "not_found"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


@dataclass
class SourceResult:
    """Normalised result returned by every source.

    ``data`` holds a small, source-specific dict of the fields the scoring
    module understands (documented in each source module).
    """

    source: str
    status: Status
    data: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "source": self.source,
            "status": self.status.value,
            "data": self.data,
            "summary": self.summary,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SourceResult:
        """Inverse of :meth:`to_dict`."""
        return cls(
            source=d["source"],
            status=Status(d["status"]),
            data=d.get("data") or {},
            summary=d.get("summary", ""),
            error=d.get("error"),
        )


class SourceError(Exception):
    """Raised for unrecoverable source failures (bad key, unexpected payload)."""


class RateLimiter:
    """Minimal thread-safe limiter enforcing a minimum interval between calls."""

    def __init__(
        self,
        per_minute: float,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.interval = 60.0 / per_minute if per_minute > 0 else 0.0
        self._sleep = sleep
        self._clock = clock
        self._last: float | None = None
        self._lock = threading.Lock()

    def wait(self) -> None:
        """Block until the next call is allowed."""
        with self._lock:
            now = self._clock()
            if self._last is not None:
                delay = self._last + self.interval - now
                if delay > 0:
                    self._sleep(delay)
                    now += delay
            self._last = now


class Source(ABC):
    """Base class for an enrichment source.

    Subclasses set the class attributes and implement :meth:`query`.
    HTTP calls should go through :meth:`request`, which applies rate
    limiting, a timeout, and retry with exponential backoff.
    """

    name: ClassVar[str]
    env_key: ClassVar[str]
    supported_types: ClassVar[frozenset[IOCType]]
    #: Requests per minute allowed by the free tier.
    rate_limit_per_minute: ClassVar[float] = 60.0

    max_retries: int = 3
    backoff_base: float = 1.0

    def __init__(
        self,
        api_key: str,
        client: httpx.Client | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=timeout, headers={"User-Agent": USER_AGENT})
        self._sleep = sleep
        self.limiter = RateLimiter(self.rate_limit_per_minute, sleep=sleep)

    def supports(self, ioc_type: IOCType) -> bool:
        """Whether this source can look up ``ioc_type``."""
        return ioc_type in self.supported_types

    def lookup(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        """Look up ``ioc``; never raises, errors are returned as results."""
        if not self.supports(ioc_type):
            return SourceResult(self.name, Status.UNSUPPORTED)
        try:
            return self.query(ioc, ioc_type)
        except (httpx.HTTPError, SourceError, ValueError, KeyError, TypeError) as exc:
            return SourceResult(self.name, Status.ERROR, error=f"{type(exc).__name__}: {exc}")

    @abstractmethod
    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        """Perform the lookup. May raise; :meth:`lookup` handles exceptions."""

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send an HTTP request with rate limiting, retries and backoff.

        Retries on transport errors, HTTP 429 and 5xx. Honours ``Retry-After``
        when present. Other responses (including 404) are returned as-is.
        """
        attempt = 0
        while True:
            self.limiter.wait()
            try:
                resp = self.client.request(method, url, **kwargs)
            except httpx.TransportError:
                if attempt >= self.max_retries:
                    raise
            else:
                if resp.status_code != 429 and resp.status_code < 500:
                    return resp
                if attempt >= self.max_retries:
                    resp.raise_for_status()
                    return resp
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                if retry_after is not None:
                    self._sleep(min(retry_after, 60.0))
                    attempt += 1
                    continue
            self._sleep(self.backoff_base * (2**attempt))
            attempt += 1

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self.client.close()


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
