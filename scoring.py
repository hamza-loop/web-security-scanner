def calculate_score(scan_results):
    score = 100
    findings = []
    positive_findings = []

    # Security Headers
    headers = scan_results.get("headers", {})

    header_checks = [
        ("HSTS", "Missing HSTS header", 15),
        ("CSP", "Missing Content Security Policy", 15),
        ("X-Content-Type-Options", "Missing X-Content-Type-Options", 10),
        ("X-Frame-Options", "Missing X-Frame-Options", 10)
    ]

    for header, message, deduction in header_checks:
        if not headers.get(header, False):
            score -= deduction
            findings.append(f"{message} (-{deduction})")
        else:
            positive_findings.append(f"{header} header is present")

    # TLS / HTTPS Security
    tls = scan_results.get("tls", {})

    if not tls.get("is_https", False):
        score -= 20
        findings.append("Insecure HTTP connection (-20)")
    else:
        positive_findings.append("HTTPS connection is in use")

        if not tls.get("valid_certificate", False):
            score -= 25
            findings.append("Invalid TLS certificate (-25)")
        else:
            positive_findings.append("TLS certificate is valid")

        if not tls.get("valid_hostname", False):
            score -= 25
            findings.append("TLS hostname validation failed (-25)")
        else:
            positive_findings.append("TLS hostname validation passed")

    # HTTP Methods
    methods = scan_results.get("methods", {})
    allowed_methods = methods.get("allowed_methods", [])

    if "TRACE" in allowed_methods:
        score -= 15
        findings.append("TRACE method is allowed (-15)")
    else:
        positive_findings.append("TRACE method is not exposed")

    # Cookie Security
    cookies = scan_results.get("cookies", [])

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
        for finding in disclosure_findings:
            if "version information" in finding:
                score -= 5
                findings.append(f"{finding} (-5)")
            else:
                score -= 2
                findings.append(f"{finding} (-2)")

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
        "findings": findings,
        "positive_findings": positive_findings
    }
