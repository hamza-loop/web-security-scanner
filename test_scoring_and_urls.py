import copy

import pytest

from finding import SecurityFinding
from scoring import calculate_score, serialize_finding
from url_utils import normalize_url


# ---------------------------------------------------------------------------
# normalize_url
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "https://example.com"),
        ("  example.com  ", "https://example.com"),
        ("http://example.com", "http://example.com"),
        ("https://example.com/path?x=1", "https://example.com/path?x=1"),
        ("example.com:8080/a", "https://example.com:8080/a"),
        ("sub.domain.example.co.in", "https://sub.domain.example.co.in"),
        ("HTTP://EXAMPLE.COM", "HTTP://EXAMPLE.COM"),
    ],
)
def test_normalize_url_accepts_valid_input(raw, expected):
    assert normalize_url(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "\t\n"])
def test_normalize_url_rejects_empty_input(raw):
    with pytest.raises(ValueError, match="empty"):
        normalize_url(raw)


@pytest.mark.parametrize(
    "raw", ["ftp://example.com", "javascript://example.com", "gopher://example.com"]
)
def test_normalize_url_rejects_unsupported_schemes(raw):
    with pytest.raises(ValueError, match="Unsupported"):
        normalize_url(raw)


@pytest.mark.parametrize("raw", ["https://", "file:///etc/passwd"])
def test_normalize_url_rejects_missing_hostname(raw):
    with pytest.raises(ValueError, match="Invalid URL"):
        normalize_url(raw)


# ---------------------------------------------------------------------------
# SecurityFinding / serialize_finding
# ---------------------------------------------------------------------------

def test_security_finding_defaults_score_impact_to_zero():
    finding = SecurityFinding("Name", "Low", "Description")
    assert finding.score_impact == 0


def test_security_finding_to_dict_contains_all_fields():
    finding = SecurityFinding("Name", "High", "Description", -15)
    assert finding.to_dict() == {
        "name": "Name",
        "severity": "High",
        "description": "Description",
        "score_impact": -15,
    }


def test_serialize_finding_converts_finding_objects():
    finding = SecurityFinding("Name", "Medium", "Description", -5)
    assert serialize_finding(finding) == finding.to_dict()


def test_serialize_finding_passes_through_strings_and_dicts():
    assert serialize_finding("plain text") == "plain text"
    assert serialize_finding({"a": 1}) == {"a": 1}


# ---------------------------------------------------------------------------
# calculate_score
# ---------------------------------------------------------------------------

PERFECT_SCAN = {
    "basic": {"url": "https://example.com/"},
    "security_headers": {
        "HSTS": {"status": "Present", "value": "max-age=31536000"},
        "CSP": {"status": "Present", "value": "default-src 'self'"},
        "X-Content-Type-Options": {"status": "Present", "value": "nosniff"},
        "X-Frame-Options": {"status": "Present", "value": "DENY"},
    },
    "tls": {"certificate_valid": True, "hostname_valid": True},
    "methods": {"allowed_methods": ["GET", "POST"]},
    "cookies": {"status": "No cookies found", "cookies": []},
    "redirects": {"security_status": "No Redirects"},
    "information_disclosure": {"findings": []},
}


def make_scan(**changes):
    scan = copy.deepcopy(PERFECT_SCAN)
    scan.update(changes)
    return scan


def test_perfect_scan_scores_100_with_no_findings():
    result = calculate_score(make_scan())
    assert result["score"] == 100
    assert result["risk_level"] == "Low Risk"
    assert result["findings"] == []


def test_perfect_scan_reports_positive_findings():
    positives = calculate_score(make_scan())["positive_findings"]
    assert "HTTPS connection is in use" in positives
    assert "TLS certificate is valid" in positives
    assert "No cookies were detected" in positives
    assert "TRACE method is not exposed" in positives


@pytest.mark.parametrize(
    "header, deduction",
    [
        ("HSTS", 15),
        ("CSP", 15),
        ("X-Content-Type-Options", 10),
        ("X-Frame-Options", 10),
    ],
)
def test_each_missing_header_deducts_expected_points(header, deduction):
    scan = make_scan()
    scan["security_headers"][header] = {"status": "Missing", "value": None}

    result = calculate_score(scan)

    assert result["score"] == 100 - deduction
    assert result["findings"][0]["score_impact"] == -deduction


def test_http_connection_deducts_20_and_becomes_medium_risk():
    result = calculate_score(make_scan(basic={"url": "http://example.com/"}))
    assert result["score"] == 80
    assert result["risk_level"] == "Medium Risk"


def test_invalid_certificate_deducts_25():
    scan = make_scan(tls={"certificate_valid": False, "hostname_valid": True})
    assert calculate_score(scan)["score"] == 75


def test_hostname_mismatch_deducts_25():
    scan = make_scan(tls={"certificate_valid": True, "hostname_valid": False})
    assert calculate_score(scan)["score"] == 75


def test_trace_method_deducts_15_and_stays_low_risk_at_boundary():
    result = calculate_score(make_scan(methods={"allowed_methods": ["TRACE"]}))
    assert result["score"] == 85
    assert result["risk_level"] == "Low Risk"


def test_insecure_cookie_loses_points_for_each_missing_flag():
    cookies = {
        "status": "Cookies analyzed",
        "cookies": [
            {"name": "sid", "secure": False, "httponly": False, "samesite": None}
        ],
    }
    result = calculate_score(make_scan(cookies=cookies))
    assert result["score"] == 75  # -10 Secure, -10 HttpOnly, -5 SameSite
    assert len(result["findings"]) == 3


def test_secure_cookie_has_no_deduction():
    cookies = {
        "status": "Cookies analyzed",
        "cookies": [
            {"name": "sid", "secure": True, "httponly": True, "samesite": "Lax"}
        ],
    }
    assert calculate_score(make_scan(cookies=cookies))["score"] == 100


def test_https_to_http_redirect_downgrade_deducts_20():
    result = calculate_score(make_scan(redirects={"security_status": "Warning"}))
    assert result["score"] == 80


@pytest.mark.parametrize("severity, deduction", [("Medium", 5), ("Low", 2)])
def test_information_disclosure_deductions_depend_on_severity(severity, deduction):
    disclosure = {
        "findings": [
            {"name": "Disclosure", "severity": severity, "description": "d"}
        ]
    }
    result = calculate_score(make_scan(information_disclosure=disclosure))
    assert result["score"] == 100 - deduction


def test_score_never_drops_below_zero():
    worst = {
        "basic": {"url": "http://example.com"},
        "security_headers": {},
        "tls": {},
        "methods": {"allowed_methods": ["TRACE"]},
        "cookies": {"cookies": []},
        "redirects": {"security_status": "Warning"},
        "information_disclosure": {"findings": []},
    }
    result = calculate_score(worst)
    assert result["score"] == 0
    assert result["risk_level"] == "High Risk"


def test_empty_input_does_not_crash_and_is_high_risk():
    # No headers (-50) and no HTTPS URL (-20). TLS is only scored for HTTPS targets.
    result = calculate_score({})
    assert result["score"] == 30
    assert result["risk_level"] == "High Risk"


def test_risk_level_boundary_at_50_is_medium_and_below_is_high():
    bad_tls = {"certificate_valid": False, "hostname_valid": False}
    assert calculate_score(make_scan(tls=bad_tls))["risk_level"] == "Medium Risk"

    low_finding = {"findings": [{"name": "x", "severity": "Low", "description": "d"}]}
    result = calculate_score(
        make_scan(tls=bad_tls, information_disclosure=low_finding)
    )
    assert result["score"] == 48
    assert result["risk_level"] == "High Risk"


def test_basic_info_key_is_accepted_as_url_fallback():
    scan = make_scan()
    del scan["basic"]
    scan["basic_info"] = {"url": "https://example.com"}
    assert calculate_score(scan)["score"] == 100