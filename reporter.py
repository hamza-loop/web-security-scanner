from html import escape


def generate_html_report(results, output_file="report.html"):
    """
    Generate an HTML security scan report.
    """

    target = results.get("target_info", {})
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

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f4f4f4;
        }}

        .container {{
            max-width: 1000px;
            margin: auto;
            background: white;
            padding: 30px;
        }}

        h1, h2 {{
            border-bottom: 1px solid #ccc;
            padding-bottom: 10px;
        }}

        .score {{
            font-size: 28px;
            font-weight: bold;
        }}

        .finding {{
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 10px;
        }}

        .severity {{
            font-weight: bold;
        }}

        .positive {{
            padding: 8px;
        }}
    </style>
</head>

<body>

<div class="container">

    <h1>Web Security Scan Report</h1>

    <h2>Target Information</h2>

    <p><strong>URL:</strong> {escape(str(target.get("url", "N/A")))}</p>
    <p><strong>HTTP Method:</strong> {escape(str(target.get("method", "N/A")))}</p>
    <p><strong>Status Code:</strong> {escape(str(target.get("status_code", "N/A")))}</p>
    <p><strong>Server:</strong> {escape(str(target.get("server", "N/A")))}</p>
    <p><strong>Content Type:</strong> {escape(str(target.get("content_type", "N/A")))}</p>

    <h2>Security Rating</h2>

    <p class="score">Score: {score}/100</p>
    <p><strong>Risk Level:</strong> {escape(str(risk_level))}</p>

    <h2>Security Issues</h2>
"""

    if not findings:
        html += "<p>No security issues detected.</p>"

    else:
        for finding in findings:
            name = escape(str(finding.get("name", "Unknown Finding")))
            severity = escape(
                str(finding.get("severity", "Unknown"))
            )
            description = escape(
                str(finding.get("description", "No description available"))
            )
            score_impact = escape(
                str(finding.get("score_impact", 0))
            )

            html += f"""
    <div class="finding">
        <p class="severity">
            {severity} — {name}
        </p>

        <p>{description}</p>

        <p>
            <strong>Score Impact:</strong>
            {score_impact}
        </p>
    </div>
"""

    html += """
    <h2>Positive Security Findings</h2>
"""

    if not positive_findings:
        html += "<p>No positive security findings recorded.</p>"

    else:
        html += "<ul>"

        for finding in positive_findings:
            html += (
                f'<li class="positive">'
                f'{escape(str(finding))}'
                f"</li>"
            )

        html += "</ul>"

    html += """
</div>

</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html)

    return output_file