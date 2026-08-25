def generate_html_report(results, output_file="report.html"):
    score_data = results.get("security_score", {})

    score = score_data.get("score", "N/A")
    risk_level = score_data.get("risk_level", "Unknown")

    findings = score_data.get("findings", [])
    positive_findings = score_data.get("positive_findings", [])

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Web Security Scan Report</title>
    </head>
    <body>
        <h1>Web Security Scan Report</h1>

        <h2>Security Rating</h2>
        <p><strong>Score:</strong> {score}/100</p>
        <p><strong>Risk Level:</strong> {risk_level}</p>

        <h2>Positive Security Findings</h2>
        <ul>
    """

    for finding in positive_findings:
        html += f"<li>{finding}</li>"

    html += """
        </ul>

        <h2>Security Issues</h2>
        <ul>
    """

    for finding in findings:
        html += f"<li>{finding}</li>"

    html += """
        </ul>

    </body>
    </html>
    """

    with open(output_file, "w") as file:
        file.write(html)

    return output_file