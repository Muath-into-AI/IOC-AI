"""Detect the type of an indicator of compromise (IOC)."""

from __future__ import annotations

import ipaddress
import re
from enum import Enum


class IOCType(str, Enum):
    """Supported IOC types."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    UNKNOWN = "unknown"

    @property
    def is_hash(self) -> bool:
        """True for file-hash types."""
        return self in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)

    @property
    def is_ip(self) -> bool:
        """True for IP address types."""
        return self in (IOCType.IPV4, IOCType.IPV6)


_HEX = re.compile(r"^[0-9a-fA-F]+$")
_HASH_LENGTHS = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}
_URL = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/$.?#][^\s]*$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$")


def detect(value: str) -> IOCType:
    """Return the :class:`IOCType` of ``value``.

    The value is expected to be already refanged (see :mod:`ioc_enrich.refang`).
    Leading/trailing whitespace is ignored.
    """
    v = value.strip()
    if not v:
        return IOCType.UNKNOWN

    if len(v) in _HASH_LENGTHS and _HEX.match(v):
        return _HASH_LENGTHS[len(v)]

    try:
        ip = ipaddress.ip_address(v.strip("[]"))
    except ValueError:
        pass
    else:
        return IOCType.IPV4 if ip.version == 4 else IOCType.IPV6

    if _URL.match(v):
        return IOCType.URL
    if _EMAIL.match(v):
        return IOCType.EMAIL
    if _DOMAIN.match(v.rstrip(".")):
        return IOCType.DOMAIN
    return IOCType.UNKNOWN
