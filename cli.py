def print_scan_result(final_results):
    """
    Display complete security scan results in the terminal.
    """

    result = final_results["target_info"]
    security_headers = final_results["security_headers"]
    cookies = final_results["cookies"]

    tls_analysis = final_results["tls"]
    redirect_results = final_results["redirects"]
    method_results = final_results["methods"]

    technology_results = final_results["technology"]
    disclosure_results = final_results["information_disclosure"]

    cors_results = final_results["cors"]
    robots_results = final_results["robots"]
    endpoint_results = final_results["endpoints"]

    score_results = final_results["security_score"]

    print("\n[+] Scan Result")
    print("    - URL:", result["url"])
    print("    - Method:", result["method"])
    print("    - Status:", result["status_code"])
    print("    - Server:", result["server"])
    print("    - Content Type:", result["content_type"])
    print("    - Redirects:", result["redirects"])
    print("    - Response Size:", result["response_size"])

    print("\n========================================")
    print(
        f"[★] SECURITY RATING: "
        f"{score_results['score']}/100 "
        f"({score_results['risk_level']})"
    )
    print("========================================")

    if score_results.get("positive_findings"):
        print("[+] Positive Security Findings:")

        for finding in score_results["positive_findings"]:
            print(f"    [✓] {finding}")

    if score_results.get("findings"):
        print("\n[!] Security Issues:")

        for finding in score_results["findings"]:

            if isinstance(finding, dict):
                print(f"    [-] {finding['name']}")
                print(f"        Severity: {finding['severity']}")
                print(
                    f"        Description: "
                    f"{finding['description']}"
                )
                print(
                    f"        Score Impact: "
                    f"{finding['score_impact']}"
                )

            else:
                print(f"    [-] {finding}")

    print("========================================")

    # Redirect security
    print("\n[+] Redirect Security")
    print(
        f"    - Redirect Count: "
        f"{redirect_results.get('redirect_count')}"
    )
    print(
        f"    - Original Scheme: "
        f"{redirect_results.get('original_scheme')}"
    )
    print(
        f"    - Final Scheme: "
        f"{redirect_results.get('final_scheme')}"
    )
    print(
        f"    - Security Status: "
        f"{redirect_results.get('security_status')}"
    )

    # Security headers
    print("\n[+] Security Headers")

    for header, details in security_headers.items():
        print(
            f"    - {header}: "
            f"{details['status']}"
        )

    # HTTP method security
    print("\n[+] HTTP Method Security")

    if method_results["status"] == "success":
        print(
            f"    - Allow Header: "
            f"{method_results['allow_header'] or 'Not disclosed'}"
        )

        print("    - Allowed Methods:")

        for method in method_results["allowed_methods"]:
            print(f"        {method}")

        print("    - Method Tests:")

        for method, details in method_results[
            "method_tests"
        ].items():
            status = (
                "Allowed"
                if details["allowed"]
                else "Blocked"
            )

            print(
                f"        {method}: "
                f"{details['status_code']} "
                f"({status})"
            )

    else:
        print(
            f"    - Status: "
            f"{method_results['status']}"
        )
        print(
            f"    - Error: "
            f"{method_results['error']}"
        )

    # Cookie security
    print("\n[+] Cookie Security")

    print(
        f"    - Status: "
        f"{cookies['status']}"
    )

    cookie_list = cookies.get("cookies", [])

    if cookie_list:
        for cookie in cookie_list:
            print(f"    - {cookie['name']}:")

            print(
                f"        Secure: "
                f"{'Present' if cookie['secure'] else 'Missing'}"
            )

            print(
                f"        HttpOnly: "
                f"{'Present' if cookie['httponly'] else 'Missing'}"
            )

            print(
                f"        SameSite: "
                f"{cookie['samesite'] or 'Missing'}"
            )

    else:
        print("    - No cookies found")

    # TLS security
    if tls_analysis:
        print("\n[+] TLS Security")

        if tls_analysis["status"] == "success":
            print(
                f"    - TLS Version: "
                f"{tls_analysis['tls_version']}"
            )

            print(
                f"    - Certificate Valid: "
                f"{tls_analysis['certificate_valid']}"
            )

            print(
                f"    - Hostname Valid: "
                f"{tls_analysis['hostname_valid']}"
            )

            print(
                f"    - Valid Until: "
                f"{tls_analysis['valid_until']}"
            )

        else:
            print(
                f"    - Status: "
                f"{tls_analysis['status']}"
            )

            print(
                f"    - Error Type: "
                f"{tls_analysis['error_type']}"
            )

            print(
                f"    - Error: "
                f"{tls_analysis['error']}"
            )

    
    # Technology detection
    print("\n[+] Technology Detection")

    print(
        f"    - Status: "
        f"{technology_results['status']}"
    )

    print(
        f"    - Technologies Found: "
        f"{technology_results['technology_count']}"
    )

    if technology_results["technologies"]:
        for technology in technology_results[
            "technologies"
        ]:
            print(
                f"        - {technology['source']}: "
                f"{technology['value']}"
            )

    else:
        print(
            "        No technology information identified"
        )

    # Information disclosure
    print("\n[+] Information Disclosure")

    print(
        f"    - Status: "
        f"{disclosure_results['status']}"
    )

    if disclosure_results["findings"]:
        print("    - Findings:")

        for finding in disclosure_results["findings"]:
            print(f"        [!] {finding}")

    else:
        print(
            "    - No unnecessary technology "
            "information disclosed"
        )

    # CORS security
    print("\n[+] CORS Security")

    print(
        f"    - Status: "
        f"{cors_results['status']}"
    )

    print(
        f"    - Allowed Origin: "
        f"{cors_results['allow_origin'] or 'Not disclosed'}"
    )

    print(
        f"    - Credentials: "
        f"{cors_results['allow_credentials'] or 'Not disclosed'}"
    )

    print(
        f"    - Allowed Methods: "
        f"{cors_results['allow_methods'] or 'Not disclosed'}"
    )

    if cors_results["findings"]:
        print("    - Findings:")

        for finding in cors_results["findings"]:
            print(f"        [!] {finding}")

    else:
        print(
            "    - No CORS security issues detected"
        )

    # robots.txt analysis
    print("\n[+] robots.txt Analysis")

    print(
        f"    - Status: "
        f"{robots_results['status']}"
    )

    print(
        f"    - URL: "
        f"{robots_results['robots_url']}"
    )

    if robots_results["status"] == "found":
        print(
            f"    - Disallowed Paths: "
            f"{robots_results['disallowed_count']}"
        )

        if robots_results["disallowed_paths"]:
            print("    - Paths:")

            for path in robots_results[
                "disallowed_paths"
            ]:
                print(f"        [i] {path}")

    elif robots_results["status"] == "error":
        print(
            f"    - Error: "
            f"{robots_results.get('error')}"
        )

    # Common endpoint discovery
    print("\n[+] Common Endpoint Discovery")

    reachable_endpoints = [
        endpoint
        for endpoint in endpoint_results
        if endpoint["reachable"]
    ]

    print(
        f"    - Reachable Endpoints: "
        f"{len(reachable_endpoints)}"
    )

    if reachable_endpoints:
        for endpoint in reachable_endpoints:
            print(
                f"        [i] "
                f"{endpoint['endpoint']} "
                f"({endpoint['status_code']})"
            )

    else:
        print("    - No common endpoints found")