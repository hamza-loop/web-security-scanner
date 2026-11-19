import json

import pytest

import app as webapp

REPORT = {
    "target_info": {"url": "https://example.com/", "status_code": 200},
    "security_score": {
        "score": 70,
        "risk_level": "Medium Risk",
        "findings": [
            "Cookie 'sid' missing SameSite attribute (-5)",
            {"name": "Missing HSTS header", "severity": "High",
             "description": "d", "score_impact": -15},
            "Cookie 'sid' missing Secure flag (-10)",
        ],
        "positive_findings": ["HTTPS connection is in use"],
    },
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    monkeypatch.setattr(webapp, "is_private_target", lambda hostname: False)
    monkeypatch.setattr(
        webapp, "run_security_scan", lambda url, timeout=10: json.loads(json.dumps(REPORT))
    )
    return webapp.app.test_client()


def post(client, url):
    return client.post("/api/scan", json={"url": url})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def test_home_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Scan website" in response.data


def test_scan_returns_report_json(client):
    response = post(client, "example.com")
    assert response.status_code == 200
    assert response.get_json()["security_score"]["score"] == 70


def test_scan_rejects_empty_url(client):
    response = post(client, "")
    assert response.status_code == 400
    assert "empty" in response.get_json()["error"]


def test_scan_rejects_unsupported_scheme(client):
    response = post(client, "ftp://example.com")
    assert response.status_code == 400


def test_scan_rejects_missing_url_field(client):
    response = client.post("/api/scan", json={})
    assert response.status_code == 400


def test_scan_rejects_non_json_body(client):
    response = client.post("/api/scan", data="url=example.com")
    assert response.status_code == 400


def test_scan_rejects_non_string_url(client):
    response = client.post("/api/scan", json={"url": 123})
    assert response.status_code == 400


def test_scanner_error_is_returned_as_502(client, monkeypatch):
    monkeypatch.setattr(
        webapp,
        "run_security_scan",
        lambda url, timeout=10: {"error": "Could not resolve hostname", "error_type": "dns"},
    )
    response = post(client, "nope.invalid")

    assert response.status_code == 502
    assert response.get_json() == {
        "error": "Could not resolve hostname",
        "error_type": "dns",
    }


# ---------------------------------------------------------------------------
# Private-network protection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "10.0.0.5", "192.168.1.1"])
def test_private_addresses_are_blocked_by_default(monkeypatch, host):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    response = webapp.app.test_client().post("/api/scan", json={"url": host})
    assert response.status_code == 403


def test_private_addresses_can_be_enabled_with_env_var(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
    monkeypatch.setattr(
        webapp, "run_security_scan", lambda url, timeout=10: json.loads(json.dumps(REPORT))
    )
    response = webapp.app.test_client().post("/api/scan", json={"url": "http://127.0.0.1"})
    assert response.status_code == 200


def test_unresolvable_hostname_is_not_treated_as_private():
    assert webapp.is_private_target("this-host-does-not-exist.invalid") is False


# ---------------------------------------------------------------------------
# normalize_findings
# ---------------------------------------------------------------------------

def test_string_findings_are_converted_to_dicts():
    result = webapp.normalize_findings(["Cookie 'sid' missing Secure flag (-10)"])
    assert result == [{
        "name": "Cookie 'sid' missing Secure flag",
        "severity": "Medium",
        "description": "",
        "score_impact": -10,
    }]


@pytest.mark.parametrize(
    "text, severity",
    [
        ("HTTPS to HTTP redirect downgrade detected (-20)", "High"),
        ("Cookie 'a' missing HttpOnly flag (-10)", "Medium"),
        ("Cookie 'a' missing SameSite attribute (-5)", "Low"),
        ("Something without points", "Low"),
    ],
)
def test_string_finding_severity_comes_from_point_deduction(text, severity):
    assert webapp.normalize_findings([text])[0]["severity"] == severity


def test_dict_findings_are_left_unchanged():
    finding = {"name": "x", "severity": "High", "description": "d", "score_impact": -15}
    assert webapp.normalize_findings([finding]) == [finding]


def test_findings_are_sorted_most_severe_first(client):
    findings = post(client, "example.com").get_json()["security_score"]["findings"]

    assert [f["severity"] for f in findings] == ["High", "Medium", "Low"]
    assert all(isinstance(f, dict) for f in findings)