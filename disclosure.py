import re


def analyze_information_disclosure(headers):
    findings = []
    exposed_headers = {}

    sensitive_headers = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version"
    ]

    for header in sensitive_headers:
        value = headers.get(header)

        if not value:
            continue

        exposed_headers[header] = value

        if re.search(r"\d", value):
            findings.append(
                f"{header} exposes version information: {value}"
            )
        else:
            findings.append(
                f"{header} discloses technology information: {value}"
            )

    if findings:
        status = "warning"
    else:
        status = "secure"

    return {
        "status": status,
        "exposed_headers": exposed_headers,
        "findings": findings
    }
