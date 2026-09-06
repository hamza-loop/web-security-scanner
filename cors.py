from finding import SecurityFinding


def analyze_cors(headers):
    allow_origin = headers.get(
        "Access-Control-Allow-Origin"
    )
    allow_credentials = headers.get(
        "Access-Control-Allow-Credentials"
    )
    allow_methods = headers.get(
        "Access-Control-Allow-Methods"
    )

    findings = []

    # Wildcard origin
    if allow_origin == "*":
        finding = SecurityFinding(
            name="Wildcard CORS Origin",
            severity="Medium",
            description=(
                "Wildcard Access-Control-Allow-Origin (*) "
                "is enabled"
            ),
        )

        findings.append(
            finding.to_dict()
        )

    # Wildcard origin with credentials
    if (
        allow_origin == "*"
        and allow_credentials
        and allow_credentials.lower() == "true"
    ):
        finding = SecurityFinding(
            name="Wildcard CORS With Credentials",
            severity="High",
            description=(
                "Wildcard CORS origin is used with "
                "credentials enabled"
            ),
        )

        findings.append(
            finding.to_dict()
        )

    return {
        "status": (
            "warning"
            if findings
            else "secure"
        ),
        "allow_origin": allow_origin,
        "allow_credentials": allow_credentials,
        "allow_methods": allow_methods,
        "findings": findings,
    }