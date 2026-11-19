"""Tests for modules that make HTTP requests.

Every request is mocked, so these tests run offline and never touch a real site.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests

import scan_engine
from endpoints import COMMON_ENDPOINTS, check_common_endpoints
from methods import analyze_methods
from robots import analyze_robots
from scanner import scan_url


def fake_response(status=200, headers=None, text="", content=b"", url="https://example.com/"):
    return SimpleNamespace(
        status_code=status,
        headers=headers or {},
        text=text,
        content=content,
        url=url,
        history=[],
    )


# ---------------------------------------------------------------------------
# scanner.scan_url
# ---------------------------------------------------------------------------

def test_scan_url_returns_response_details():
    response = fake_response(
        headers={"Server": "nginx", "Content-Type": "text/html"},
        content=b"hello",
    )
    with patch("scanner.requests.request", return_value=response):
        result = scan_url("https://example.com/")

    assert result["status_code"] == 200
    assert result["server"] == "nginx"
    assert result["content_type"] == "text/html"
    assert result["response_size"] == 5
    assert result["redirects"] == 0


def test_scan_url_uses_unknown_when_headers_are_absent():
    with patch("scanner.requests.request", return_value=fake_response()):
        result = scan_url("https://example.com/")

    assert result["server"] == "unknown"
    assert result["content_type"] == "unknown"


def test_scan_url_sends_scanner_user_agent():
    with patch("scanner.requests.request", return_value=fake_response()) as mocked:
        scan_url("https://example.com/", method="HEAD", timeout=3)

    args, kwargs = mocked.call_args
    assert args == ("HEAD", "https://example.com/")
    assert kwargs["timeout"] == 3
    assert "Security-Scanner" in kwargs["headers"]["User-Agent"]


def test_scan_url_reports_timeout():
    with patch("scanner.requests.request", side_effect=requests.exceptions.Timeout()):
        result = scan_url("https://slow.example.com/")

    assert result["error_type"] == "timeout"


def test_scan_url_reports_dns_failure():
    error = requests.exceptions.ConnectionError("NameResolutionError: no such host")
    with patch("scanner.requests.request", side_effect=error):
        result = scan_url("https://nope.invalid/")

    assert result["error_type"] == "dns"
    assert result["error"] == "Could not resolve hostname"


def test_scan_url_reports_connection_failure():
    error = requests.exceptions.ConnectionError("Connection refused")
    with patch("scanner.requests.request", side_effect=error):
        result = scan_url("https://example.com/")

    assert result["error_type"] == "connection"


def test_scan_url_reports_other_request_errors():
    error = requests.exceptions.InvalidURL("bad url")
    with patch("scanner.requests.request", side_effect=error):
        result = scan_url("https://example.com/")

    assert result["error_type"] == "request"


# ---------------------------------------------------------------------------
# methods.analyze_methods
# ---------------------------------------------------------------------------

def test_methods_parses_allow_header_into_uppercase_list():
    options = fake_response(headers={"Allow": "get, post ,TRACE"})
    with patch("methods.requests.options", return_value=options), patch(
        "methods.requests.request", return_value=fake_response(405)
    ):
        result = analyze_methods("https://example.com/")

    assert result["status"] == "success"
    assert result["allowed_methods"] == ["GET", "POST", "TRACE"]


def test_methods_without_allow_header_gives_empty_list():
    with patch("methods.requests.options", return_value=fake_response()), patch(
        "methods.requests.request", return_value=fake_response(405)
    ):
        result = analyze_methods("https://example.com/")

    assert result["allowed_methods"] == []


@pytest.mark.parametrize(
    "status, expected",
    [(200, True), (204, True), (399, True), (400, False), (405, False), (500, False)],
)
def test_methods_marks_status_below_400_as_allowed(status, expected):
    with patch("methods.requests.options", return_value=fake_response()), patch(
        "methods.requests.request", return_value=fake_response(status)
    ):
        result = analyze_methods("https://example.com/")

    assert set(result["method_tests"]) == {"TRACE", "PUT", "DELETE", "PATCH"}
    assert result["method_tests"]["TRACE"]["allowed"] is expected


def test_methods_reports_failure_when_request_raises():
    with patch(
        "methods.requests.options", side_effect=requests.exceptions.ConnectionError("boom")
    ):
        result = analyze_methods("https://example.com/")

    assert result["status"] == "failed"
    assert "boom" in result["error"]


# ---------------------------------------------------------------------------
# robots.analyze_robots
# ---------------------------------------------------------------------------

def test_robots_404_is_reported_as_not_found():
    with patch("robots.requests.get", return_value=fake_response(404)):
        result = analyze_robots("https://example.com/")

    assert result["status"] == "not_found"


def test_robots_server_error_is_reported_with_status_code():
    with patch("robots.requests.get", return_value=fake_response(500)):
        result = analyze_robots("https://example.com/")

    assert result["status"] == "error"
    assert result["findings"] == ["robots.txt returned HTTP 500"]


def test_robots_collects_disallowed_paths_and_ignores_empty_rules():
    body = "User-agent: *\nDisallow: /admin\nDisallow: /private/\nDisallow:\nAllow: /\n"
    with patch("robots.requests.get", return_value=fake_response(200, text=body)):
        result = analyze_robots("https://example.com/")

    assert result["status"] == "found"
    assert result["disallowed_paths"] == ["/admin", "/private/"]
    assert result["disallowed_count"] == 2


def test_robots_disallow_keyword_is_case_insensitive():
    body = "DISALLOW: /secret\n"
    with patch("robots.requests.get", return_value=fake_response(200, text=body)):
        result = analyze_robots("https://example.com/")

    assert result["disallowed_paths"] == ["/secret"]


def test_robots_url_is_built_from_site_root():
    with patch("robots.requests.get", return_value=fake_response(404)) as mocked:
        result = analyze_robots("https://example.com/deep/page?x=1")

    assert result["robots_url"] == "https://example.com/robots.txt"
    assert mocked.call_args[0][0] == "https://example.com/robots.txt"


def test_robots_network_error_is_handled():
    with patch(
        "robots.requests.get", side_effect=requests.exceptions.Timeout("slow")
    ):
        result = analyze_robots("https://example.com/")

    assert result["status"] == "error"


# ---------------------------------------------------------------------------
# endpoints.check_common_endpoints
# ---------------------------------------------------------------------------

def test_endpoints_checks_every_common_path():
    with patch("endpoints.requests.get", return_value=fake_response(404)):
        results = check_common_endpoints("https://example.com/")

    assert [r["endpoint"] for r in results] == COMMON_ENDPOINTS


def test_endpoints_reachable_depends_on_status_code():
    with patch("endpoints.requests.get", return_value=fake_response(200)):
        reachable = check_common_endpoints("https://example.com/")
    with patch("endpoints.requests.get", return_value=fake_response(404)):
        missing = check_common_endpoints("https://example.com/")

    assert all(r["reachable"] for r in reachable)
    assert not any(r["reachable"] for r in missing)


def test_endpoints_are_resolved_from_the_site_root():
    with patch("endpoints.requests.get", return_value=fake_response(404)):
        results = check_common_endpoints("https://example.com/some/page")

    assert results[0]["url"] == "https://example.com/admin"


def test_endpoints_network_error_is_recorded_per_endpoint():
    with patch(
        "endpoints.requests.get", side_effect=requests.exceptions.ConnectionError("down")
    ):
        results = check_common_endpoints("https://example.com/")

    assert len(results) == len(COMMON_ENDPOINTS)
    assert all(r["status_code"] is None and r["reachable"] is False for r in results)


# ---------------------------------------------------------------------------
# scan_engine.run_security_scan
# ---------------------------------------------------------------------------

SCAN_RESULT = {
    "url": "https://example.com/",
    "method": "GET",
    "status_code": 200,
    "server": "nginx",
    "content_type": "text/html",
    "redirects": 0,
    "response_size": 10,
    "headers": {"Server": "nginx"},
    "redirect_history": [],
}


@pytest.fixture
def stub_network(monkeypatch):
    monkeypatch.setattr(scan_engine, "scan_url", lambda *a, **k: dict(SCAN_RESULT))
    monkeypatch.setattr(
        scan_engine, "analyze_methods", lambda *a, **k: {"status": "success", "allowed_methods": []}
    )
    monkeypatch.setattr(scan_engine, "analyze_robots", lambda *a, **k: {"status": "not_found"})
    monkeypatch.setattr(scan_engine, "check_common_endpoints", lambda *a, **k: [])
    monkeypatch.setattr(
        scan_engine,
        "analyze_tls",
        lambda *a, **k: {"status": "success", "certificate_valid": True, "hostname_valid": True},
    )


def test_run_security_scan_returns_scan_errors_unchanged(monkeypatch):
    error = {"url": "https://x", "error_type": "dns", "error": "Could not resolve hostname"}
    monkeypatch.setattr(scan_engine, "scan_url", lambda *a, **k: error)

    assert scan_engine.run_security_scan("https://x") == error


def test_run_security_scan_builds_full_report(stub_network):
    report = scan_engine.run_security_scan("https://example.com/")

    expected_sections = {
        "target_info", "security_headers", "cookies", "tls", "redirects", "methods",
        "technology", "information_disclosure", "cors", "robots", "endpoints",
        "security_score",
    }
    assert expected_sections <= set(report)
    assert report["target_info"]["status_code"] == 200


def test_run_security_scan_skips_tls_for_http_targets(monkeypatch, stub_network):
    http_result = dict(SCAN_RESULT, url="http://example.com/")
    monkeypatch.setattr(scan_engine, "scan_url", lambda *a, **k: dict(http_result))

    report = scan_engine.run_security_scan("http://example.com/")

    assert report["tls"] == {}
    assert report["security_score"]["score"] < 100


def test_run_security_scan_score_matches_missing_headers(stub_network):
    report = scan_engine.run_security_scan("https://example.com/")
    names = [f["name"] for f in report["security_score"]["findings"] if isinstance(f, dict)]

    assert "Missing HSTS header" in names
    assert "Missing Content Security Policy" in names