from reporter import generate_html_report

test_results = {
    "security_score": {
        "score": 75,
        "risk_level": "Medium Risk",
        "findings": [
            "Missing Content Security Policy",
            "Missing HSTS header"
        ],
        "positive_findings": [
            "HTTPS connection is in use",
            "TLS certificate is valid"
        ]
    }
}

output_file = generate_html_report(
    test_results,
    "test_report.html"
)

print(f"Report created successfully: {output_file}")