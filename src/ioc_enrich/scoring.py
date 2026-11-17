"""Risk scoring: turn source results into a 0-100 score with reasons.

Weighting (points are summed, then clamped to 0-100):

=============  ===============================================  ======
Source         Signal                                           Points
=============  ===============================================  ======
VirusTotal     >= 10 engines malicious                          50
               3-9 engines malicious                            35
               1-2 engines malicious                            15
               any engine "suspicious" (bonus, VT capped at 50)  5
AbuseIPDB      abuse confidence score x 0.4                     0-40
               IP is on AbuseIPDB's whitelist                   -10
URLhaus        IOC is listed                                    30
               listed URL still online / host has online URLs   +10
MalwareBazaar  hash is a known sample                           40
OTX            >= 10 pulses                                     20
               3-9 pulses                                       12
               1-2 pulses                                       5
=============  ===============================================  ======

Risk levels: 0 = ``none``, 1-29 = ``low``, 30-59 = ``medium``,
60-79 = ``high``, 80-100 = ``critical``.  If no source returned data the
level is ``unknown``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ioc_enrich.detect import IOCType
from ioc_enrich.sources.base import SourceResult, Status

LEVELS: tuple[tuple[int, str], ...] = (
    (80, "critical"),
    (60, "high"),
    (30, "medium"),
    (1, "low"),
    (0, "none"),
)


@dataclass
class Score:
    """A risk score with human-readable reasons."""

    value: int
    level: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class EnrichmentResult:
    """Everything known about one IOC after enrichment."""

    ioc: str
    original: str
    ioc_type: IOCType
    results: list[SourceResult]
    score: Score

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "ioc": self.ioc,
            "original": self.original,
            "type": self.ioc_type.value,
            "score": self.score.value,
            "level": self.score.level,
            "reasons": self.score.reasons,
            "sources": [r.to_dict() for r in self.results],
        }


def level_for(value: int) -> str:
    """Map a numeric score to a risk level."""
    for threshold, name in LEVELS:
        if value >= threshold:
            return name
    return "none"


def _virustotal(d: dict[str, Any]) -> tuple[int, list[str]]:
    mal = int(d.get("malicious", 0))
    sus = int(d.get("suspicious", 0))
    pts = 50 if mal >= 10 else 35 if mal >= 3 else 15 if mal >= 1 else 0
    reasons = [f"VirusTotal: {mal} engines flag as malicious"] if mal else []
    if sus:
        pts += 5
        reasons.append(f"VirusTotal: {sus} engines flag as suspicious")
    return min(pts, 50), reasons


def _abuseipdb(d: dict[str, Any]) -> tuple[int, list[str]]:
    conf = int(d.get("abuse_confidence", 0))
    pts = round(conf * 0.4)
    reasons = []
    if conf:
        reasons.append(f"AbuseIPDB: {conf}% abuse confidence ({d.get('total_reports', 0)} reports)")
    if d.get("is_whitelisted"):
        pts -= 10
        reasons.append("AbuseIPDB: IP is whitelisted")
    return pts, reasons


def _urlhaus(d: dict[str, Any]) -> tuple[int, list[str]]:
    if not d.get("listed"):
        return 0, []
    pts = 30
    threat = d.get("threat") or d.get("signature")
    reasons = ["URLhaus: listed" + (f" ({threat})" if threat else "")]
    if d.get("url_status") == "online" or int(d.get("online", 0) or 0) > 0:
        pts += 10
        reasons.append("URLhaus: malicious URL still online")
    return pts, reasons


def _malwarebazaar(d: dict[str, Any]) -> tuple[int, list[str]]:
    if not d.get("listed"):
        return 0, []
    sig = d.get("signature")
    return 40, ["MalwareBazaar: known malware sample" + (f" ({sig})" if sig else "")]


def _otx(d: dict[str, Any]) -> tuple[int, list[str]]:
    n = int(d.get("pulse_count", 0))
    pts = 20 if n >= 10 else 12 if n >= 3 else 5 if n >= 1 else 0
    return pts, ([f"OTX: referenced in {n} pulses"] if n else [])


_SCORERS = {
    "virustotal": _virustotal,
    "abuseipdb": _abuseipdb,
    "urlhaus": _urlhaus,
    "malwarebazaar": _malwarebazaar,
    "otx": _otx,
}


def score(results: Iterable[SourceResult]) -> Score:
    """Compute a :class:`Score` from a set of source results."""
    total = 0
    reasons: list[str] = []
    answered = False
    for r in results:
        if r.status not in (Status.FOUND, Status.NOT_FOUND):
            continue
        answered = True
        scorer = _SCORERS.get(r.source)
        if scorer is None:
            continue
        pts, why = scorer(r.data)
        total += pts
        reasons.extend(why)
    value = max(0, min(100, total))
    if not answered:
        return Score(0, "unknown", ["no source returned data"])
    if not reasons:
        reasons.append("no source reported malicious activity")
    return Score(value, level_for(value), reasons)
