from reporter import (
    generate_html_report,
    generate_json_report,
)


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
            ],
            "positive_findings": [
                "HTTPS connection is in use",
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


def test_generate_json_report(tmp_path):
    results = {
        "target_info": {
            "url": "https://example.com",
            "status_code": 200,
        },
        "security_score": {
            "score": 75,
            "risk_level": "Medium Risk",
        },
    }

    output_file = tmp_path / "report.json"

    result = generate_json_report(
        results,
        output_file,
    )

    assert result == output_file
    assert output_file.exists()

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert '"url": "https://example.com"' in content
    assert '"score": 75' in content
    assert '"risk_level": "Medium Risk"' in content