from finding import SecurityFinding


def test_security_finding_attributes():
    finding = SecurityFinding(
        "Missing HSTS",
        "High",
        "The target does not enforce HTTPS connections.",
        -15,
    )

    assert finding.name == "Missing HSTS"
    assert finding.severity == "High"
    assert finding.description == "The target does not enforce HTTPS connections."
    assert finding.score_impact == -15


def test_security_finding_to_dict():
    finding = SecurityFinding(
        "Missing CSP",
        "High",
        "The target does not define a Content Security Policy.",
        -15,
    )

    result = finding.to_dict()

    assert result == {
        "name": "Missing CSP",
        "severity": "High",
        "description": "The target does not define a Content Security Policy.",
        "score_impact": -15,
    }