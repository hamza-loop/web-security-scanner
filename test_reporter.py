from reporter import generate_html_report


def test_generate_html_report(tmp_path):
    results = {
        "target_info": {
            "url": "https://example.com",
            "method": "GET",
            "status_code": 200,
            "server": "ExampleServer",
            "content_type": "text/html",
        },
        "security_score": {
            "score": 75,
            "risk_level": "Medium Risk",
            "findings": [
                {
                    "name": "Missing Content Security Policy",
                    "severity": "High",
                    "description": (
                        "The target does not define a "
                        "Content Security Policy."
                    ),
                    "score_impact": -15,
                },
                {
                    "name": "Missing HSTS Header",
                    "severity": "High",
                    "description": (
                        "The target does not enforce "
                        "HTTP Strict Transport Security."
                    ),
                    "score_impact": -15,
                },
            ],
            "positive_findings": [
                "HTTPS connection is in use",
                "TLS certificate is valid",
            ],
        },
    }

    output_file = tmp_path / "report.html"

    result = generate_html_report(
        results,
        output_file,
    )

    assert result == output_file
    assert output_file.exists()

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert "Web Security Scan Report" in content
    assert "https://example.com" in content
    assert "75/100" in content
    assert "Medium Risk" in content
    assert "Missing Content Security Policy" in content
    assert "Missing HSTS Header" in content
    assert "HTTPS connection is in use" in content