import re

from finding import SecurityFinding


def analyze_information_disclosure(headers):
    findings = []
    exposed_headers = {}

    sensitive_headers = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
    ]

    for header in sensitive_headers:
        value = headers.get(header)

        if not value:
            continue

        exposed_headers[header] = value

        if re.search(r"\d", value):
            finding = SecurityFinding(
                name="Version Information Disclosure",
                severity="Medium",
                description=(
                    f"{header} exposes version information: {value}"
                ),
            )

        else:
            finding = SecurityFinding(
                name="Technology Information Disclosure",
                severity="Low",
                description=(
                    f"{header} discloses technology information: {value}"
                ),
            )

        findings.append(finding.to_dict())

    if findings:
        status = "warning"
    else:
        status = "secure"

    return {
        "status": status,
        "exposed_headers": exposed_headers,
        "findings": findings,
    }