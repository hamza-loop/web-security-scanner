import requests

from scanner import scan_url


def test_scan_url_timeout(monkeypatch):
    def mock_request(*args, **kwargs):
        raise requests.exceptions.Timeout()

    monkeypatch.setattr(requests, "request", mock_request)

    result = scan_url("https://example.com")

    assert result["error_type"] == "timeout"
    assert result["error"] == "Connection timed out"


def test_scan_url_connection_error(monkeypatch):
    def mock_request(*args, **kwargs):
        raise requests.exceptions.ConnectionError(
            "Could not connect"
        )

    monkeypatch.setattr(requests, "request", mock_request)

    result = scan_url("https://example.com")

    assert result["error_type"] == "connection"
    assert result["error"] == "Could not connect to target"


def test_scan_url_generic_request_error(monkeypatch):
    def mock_request(*args, **kwargs):
        raise requests.exceptions.RequestException(
            "Something went wrong"
        )

    monkeypatch.setattr(requests, "request", mock_request)

    result = scan_url("https://example.com")

    assert result["error_type"] == "request"
    assert result["error"] == "Something went wrong"