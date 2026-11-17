"""Refang defanged indicators (e.g. ``hxxp://example[.]com`` -> ``http://example.com``)."""

from __future__ import annotations

import re

_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    # Schemes: hxxp, hXXps, fxp, meow -> http(s)/ftp
    (re.compile(r"^h(?:xx|XX|tt|TT|\*\*)p(s?)(?=\[?:)", re.IGNORECASE), r"http\1"),
    (re.compile(r"^fxp(s?)(?=\[?:)", re.IGNORECASE), r"ftp\1"),
    # Scheme separator: [:]//, [://], :\/\/
    (re.compile(r"\[:\]//|\[://\]|:\\/\\/"), "://"),
    # Dots: [.], (.), {.}, [dot], (dot), " dot "
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\s*[\[\(\{]dot[\]\)\}]\s*", re.IGNORECASE), "."),
    # At-sign: [@], (@), [at], (at)
    (re.compile(r"\[@\]|\(@\)|\{@\}"), "@"),
    (re.compile(r"\s*[\[\(\{]at[\]\)\}]\s*", re.IGNORECASE), "@"),
    # Colons in IPv6/ports: [:]
    (re.compile(r"\[:\]"), ":"),
]


def refang(value: str) -> str:
    """Return ``value`` with common defanging patterns reversed.

    Already-fanged input is returned unchanged (apart from stripped whitespace).
    """
    v = value.strip()
    for pattern, repl in _REPLACEMENTS:
        v = pattern.sub(repl, v)
    return v
