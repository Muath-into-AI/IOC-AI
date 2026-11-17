import pytest

from ioc_enrich.detect import IOCType, detect


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5),
        ("3395856CE81F2B7382DEE72602F798B642F14140", IOCType.SHA1),
        (
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            IOCType.SHA256,
        ),
        ("8.8.8.8", IOCType.IPV4),
        ("2001:4860:4860::8888", IOCType.IPV6),
        ("example.com", IOCType.DOMAIN),
        ("sub.example.co.uk", IOCType.DOMAIN),
        ("http://example.com/path?q=1", IOCType.URL),
        ("https://example.com", IOCType.URL),
        ("user@example.com", IOCType.EMAIL),
        ("", IOCType.UNKNOWN),
        ("not an ioc", IOCType.UNKNOWN),
        ("999.1.1.1", IOCType.UNKNOWN),
        ("zzzz8612fea8a8f36de82e1278abb02f", IOCType.UNKNOWN),
    ],
)
def test_detect(value: str, expected: IOCType) -> None:
    assert detect(value) is expected


def test_whitespace_is_ignored() -> None:
    assert detect("  8.8.8.8\n") is IOCType.IPV4


def test_type_helpers() -> None:
    assert IOCType.MD5.is_hash
    assert not IOCType.DOMAIN.is_hash
    assert IOCType.IPV6.is_ip
    assert not IOCType.URL.is_ip
