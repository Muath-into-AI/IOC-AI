import pytest

from ioc_enrich.detect import IOCType, detect
from ioc_enrich.refang import refang


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("hxxp://example[.]com", "http://example.com"),
        ("hXXps://evil(.)example[.]org/a", "https://evil.example.org/a"),
        ("http[:]//example.com", "http://example.com"),
        ("example[dot]com", "example.com"),
        ("8.8.8[.]8", "8.8.8.8"),
        ("8(.)8(.)8(.)8", "8.8.8.8"),
        ("user[@]example[.]com", "user@example.com"),
        ("user[at]example[.]com", "user@example.com"),
        ("fxp://files[.]example[.]com", "ftp://files.example.com"),
        ("2001[:]db8::1", "2001:db8::1"),
        ("  example.com  ", "example.com"),
        ("http://already.fanged/", "http://already.fanged/"),
    ],
)
def test_refang(value: str, expected: str) -> None:
    assert refang(value) == expected


def test_refang_then_detect() -> None:
    assert detect(refang("hxxp://example[.]com")) is IOCType.URL
