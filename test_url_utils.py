import pytest

from url_utils import normalize_url


def test_adds_https_to_domain():
    assert normalize_url("example.com") == "https://example.com"


def test_preserves_https():
    assert normalize_url("https://example.com") == "https://example.com"


def test_strips_whitespace():
    assert normalize_url("  example.com  ") == "https://example.com"


def test_rejects_unsupported_scheme():
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")