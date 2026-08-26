def analyze_cors(headers):

    allow_origin = headers.get("Access-Control-Allow-Origin")
    allow_credentials = headers.get("Access-Control-Allow-Credentials")
    allow_methods = headers.get("Access-Control-Allow-Methods")

    findings = []

    if allow_origin == "*":
        findings.append(
            "Wildcard Access-Control-Allow-Origin (*) is enabled"
        )

    if allow_origin == "*" and allow_credentials and allow_credentials.lower() == "true":
        findings.append(
            "Wildcard CORS origin is used with credentials enabled"
        )

    return {
        "status": "warning" if findings else "secure",
        "allow_origin": allow_origin,
        "allow_credentials": allow_credentials,
        "allow_methods": allow_methods,
        "findings": findings
    }