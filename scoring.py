from finding import SecurityFinding

def serialize_finding(finding):
    if isinstance(finding, SecurityFinding):
        return finding.to_dict()

    return finding

def calculate_score(scan_results):
    score = 100
    findings = []
    positive_findings = []

    # Security Headers
    headers = scan_results.get("security_headers", {})

    header_checks = [
    (
        "HSTS",
        "Missing HSTS header",
        "High",
        "The target does not enforce HTTP Strict Transport Security.",
        15,
    ),
    (
        "CSP",
        "Missing Content Security Policy",
        "High",
        "The target does not define a Content Security Policy.",
        15,
    ),
    (
        "X-Content-Type-Options",
        "Missing X-Content-Type-Options",
        "Medium",
        "The target may allow MIME type sniffing.",
        10,
    ),
    (
        "X-Frame-Options",
        "Missing X-Frame-Options",
        "Medium",
        "The target may be vulnerable to clickjacking.",
        10,
    ),
]

    for header, name, severity, description, deduction in header_checks:
        header_result = headers.get(header, {})

        if header_result.get("status") != "Present":
            score -= deduction

            finding = SecurityFinding(
                name,
                severity,
                description,
                -deduction,
            )

            findings.append(finding)
        else:
            positive_findings.append(f"{header} header is present")
    # TLS / HTTPS Security
    tls = scan_results.get("tls", {})

    if not tls.get("is_https", False):
        score -= 20

        finding = SecurityFinding(
            "Insecure HTTP Connection",
            "High",
            "The target is using an insecure HTTP connection.",
            -20,
        )

        findings.append(finding)

    else:
        positive_findings.append("HTTPS connection is in use")

        if not tls.get("certificate_valid", False):
            score -= 25

            finding = SecurityFinding(
                "Invalid TLS Certificate",
                "High",
                "The target's TLS certificate is invalid.",
                -25,
            )

            findings.append(finding)

        else:
            positive_findings.append("TLS certificate is valid")

        if not tls.get("hostname_valid", False):
            score -= 25

            finding = SecurityFinding(
                "TLS Hostname Validation Failed",
                "High",
                "The TLS certificate hostname does not match the target.",
                -25,
            )

            findings.append(finding)

        else:
            positive_findings.append("TLS hostname validation passed")

    # HTTP Methods
    methods = scan_results.get("methods", {})
    allowed_methods = methods.get("allowed_methods", [])

    if "TRACE" in allowed_methods:
        score -= 15

        finding = SecurityFinding(
            "TRACE Method Enabled",
            "High",
            "The TRACE HTTP method is enabled and may expose sensitive request information.",
            -15,
        )

        findings.append(finding)

    else:
        positive_findings.append("TRACE method is not exposed")

    # Cookie Security
    cookie_results = scan_results.get("cookies", {})
    cookies = cookie_results.get("cookies", [])
    if not cookies:
        positive_findings.append("No cookies were detected")
    else:
        for cookie in cookies:
            cookie_name = cookie.get("name", "Unknown")

            if not cookie.get("secure", False):
                score -= 10
                findings.append(
                    f"Cookie '{cookie_name}' missing Secure flag (-10)"
                )

            if not cookie.get("httponly", False):
                score -= 10
                findings.append(
                    f"Cookie '{cookie_name}' missing HttpOnly flag (-10)"
                )

            if not cookie.get("samesite"):
                score -= 5
                findings.append(
                    f"Cookie '{cookie_name}' missing SameSite attribute (-5)"
                )

    # Redirect Security
    redirects = scan_results.get("redirects", {})

    if redirects.get("security_status") == "Warning":
        score -= 20
        findings.append(
            "HTTPS to HTTP redirect downgrade detected (-20)"
        )
    else:
        positive_findings.append(
            "No HTTPS to HTTP redirect downgrade detected"
        )

    # Information Disclosure
    disclosure = scan_results.get("information_disclosure", {})

    disclosure_findings = disclosure.get("findings", [])

    if not disclosure_findings:
        positive_findings.append(
            "No unnecessary technology information was disclosed"
        )
    else:
        for disclosure_finding in disclosure_findings:

            if "version information" in disclosure_finding:
                deduction = 5
                severity = "Medium"
            else:
                deduction = 2
                severity = "Low"

            score -= deduction

            finding = SecurityFinding(
                "Information Disclosure",
                severity,
                disclosure_finding,
                -deduction,
            )

            findings.append(finding)
    # Keep score between 0 and 100
    score = max(0, min(score, 100))

    # Determine risk level
    if score >= 85:
        risk = "Low Risk"
    elif score >= 50:
        risk = "Medium Risk"
    else:
        risk = "High Risk"

    return {
        "score": score,
        "risk_level": risk,
        "findings": [
            serialize_finding(finding)
            for finding in findings
        ],
        "positive_findings": positive_findings
    }