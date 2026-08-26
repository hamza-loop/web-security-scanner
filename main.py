import argparse
import json
from urllib.parse import urlparse

from scanner import scan_url
from headers import check_security_headers
from cookies import check_cookie_security
from tls import analyze_tls
from redirects import analyze_redirects
from methods import analyze_methods
from technology import analyze_technology
from disclosure import analyze_information_disclosure
from scoring import calculate_score
from reporter import generate_html_report
from cors import analyze_cors
from robots import analyze_robots


parser = argparse.ArgumentParser(description="Web Security Scanner")

parser.add_argument("url", help="Target URL")

parser.add_argument(
    "--method",
    choices=["GET", "HEAD"],
    default="GET",
    help="HTTP method to use"
)

parser.add_argument(
    "--timeout",
    type=int,
    default=10,
    help="Request timeout in seconds"
)
parser.add_argument(
    "--json",
    action="store_true",
    help="Display results in JSON format"
)

parser.add_argument(
    "--output",
    help="Save scan results to a JSON file"
)

parser.add_argument(
    "--html",
    help="Save the scan report as an HTML file"
)

args = parser.parse_args()

result = scan_url(
    args.url,
    args.method,
    args.timeout
)

if "error" in result:
    print("[-] Request failed:", result["error"])
else:
    security_headers = check_security_headers(result["headers"])
    cookies = check_cookie_security(result["headers"])
    redirect_results = analyze_redirects(result)
    method_results = analyze_methods(result["url"], args.timeout)
    technology_results = analyze_technology(result["headers"])
    disclosure_results = analyze_information_disclosure(result["headers"])
    cors_results = analyze_cors(result["headers"])
    cors_results = analyze_cors(result["headers"])

    robots_results = analyze_robots(
        result["url"],
        args.timeout
    )


    parsed_url = urlparse(result["url"])
    tls_analysis = None

    if parsed_url.scheme == "https":
        tls_analysis = analyze_tls(parsed_url.hostname)

    scoring_input = {
        "headers": {
            "HSTS": security_headers.get("HSTS", {}).get("status") == "Present",
            "CSP": security_headers.get("CSP", {}).get("status") == "Present",
            "X-Content-Type-Options": (
                security_headers.get("X-Content-Type-Options", {}).get("status")
                == "Present"
            ),
        "X-Frame-Options": (
            security_headers.get("X-Frame-Options", {}).get("status")
            == "Present"
        )
    },
    "tls": {
        "is_https": parsed_url.scheme == "https",
        "valid_certificate": (
            tls_analysis.get("certificate_valid", False)
            if tls_analysis
            else False
        ),
        "valid_hostname": (
            tls_analysis.get("hostname_valid", False)
            if tls_analysis
            else False
        )
    },
    "methods": {
        "allowed_methods": (
            method_results.get("allowed_methods", [])
            if method_results.get("status") == "success"
            else []
        )
    },
    "cookies": cookies,
    "redirects": redirect_results,
    "information_disclosure": disclosure_results
}

    score_results = calculate_score(scoring_input)

    final_results = {
        "target_info": {
            "url": result["url"],
            "method": result["method"],
            "status_code": result["status_code"],
            "server": result["server"],
            "content_type": result["content_type"],
            "redirects": result["redirects"],
            "response_size": result["response_size"]
        },
        "security_headers": security_headers,
        "cookies": cookies,
        "tls_analysis": tls_analysis,
        "redirect_analysis": redirect_results,
        "method_analysis": method_results,
        "technology_analysis": technology_results,
        "information_disclosure": disclosure_results,
        "cors_analysis": cors_results,
        "robots_analysis": robots_results,
        "security_score": score_results
    }

    if args.json:
        print(json.dumps(final_results, indent=4))
        exit()

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
            print(f"    [-] {finding}")

    print("========================================")

    print("\n[+] Redirect Security")
    print(f"    - Redirect Count: {redirect_results.get('redirect_count')}")
    print(f"    - Original Scheme: {redirect_results.get('original_scheme')}")
    print(f"    - Final Scheme: {redirect_results.get('final_scheme')}")
    print(f"    - Security Status: {redirect_results.get('security_status')}")

    print("\n[+] Security Headers")

    for header, details in security_headers.items():
        print(f"    - {header}: {details['status']}")

    print("\n[+] HTTP Method Security")

    if method_results["status"] == "success":
        print(f"    - Allow Header: {method_results['allow_header'] or 'Not disclosed'}")

        print("    - Allowed Methods:")
        for method in method_results["allowed_methods"]:
            print(f"        {method}")

        print("    - Method Tests:")
        for method, details in method_results["method_tests"].items():
            status = "Allowed" if details["allowed"] else "Blocked"
            print(f"        {method}: {details['status_code']} ({status})")
    else:
        print(f"    - Status: {method_results['status']}")
        print(f"    - Error: {method_results['error']}")

    print("\n[+] Cookie Security")

    if cookies:
        for cookie in cookies:
            print(f"    - {cookie['name']}:")
            print(f"        Secure: {'Present' if cookie['secure'] else 'Missing'}")
            print(f"        HttpOnly: {'Present' if cookie['httponly'] else 'Missing'}")
            print(f"        SameSite: {cookie['samesite'] or 'Missing'}")
    else:
        print("    - No cookies found")

    if tls_analysis:
        print("\n[+] TLS Security")

        if tls_analysis["status"] == "success":
            print(f"    - TLS Version: {tls_analysis['tls_version']}")
            print(f"    - Certificate Valid: {tls_analysis['certificate_valid']}")
            print(f"    - Hostname Valid: {tls_analysis['hostname_valid']}")
            print(f"    - Valid Until: {tls_analysis['valid_until']}")
        else:
            print(f"    - Status: {tls_analysis['status']}")
            print(f"    - Error Type: {tls_analysis['error_type']}")
            print(f"    - Error: {tls_analysis['error']}")

    print("\n[+] Technology Detection")
    print(f"    - Status: {technology_results['status']}")
    print(f"    - Technologies Found: {technology_results['technology_count']}")
    
    if technology_results["technologies"]:
        for technology in technology_results["technologies"]:
            print(f"        - {technology['source']}: {technology['value']}")
    else:
        print("        No technology information identified")

    print("\n[+] Information Disclosure")

    print(f"    - Status: {disclosure_results['status']}")

    if disclosure_results["findings"]:
        print("    - Findings:")
        for finding in disclosure_results["findings"]:
            print(f"        [!] {finding}")
    else:
        print("    - No unnecessary technology information disclosed")
    
    if args.output:
        try:
            with open(args.output, "w") as file:
                json.dump(final_results, file, indent=4)

            print(f"\n[+] Report saved to: {args.output}")

        except OSError as error:
            print(f"\n[-] Failed to save report: {error}")
    
    if args.html:
        try:
            generate_html_report(final_results, args.html)
            print(f"\n[+] HTML report saved to: {args.html}")
        except OSError as error:
            print(f"\n[-] Failed to save HTML report: {error}")
    
    print("\n[+] CORS Security")

    print(f"    - Status: {cors_results['status']}")
    print(f"    - Allowed Origin: {cors_results['allow_origin'] or 'Not disclosed'}")
    print(f"    - Credentials: {cors_results['allow_credentials'] or 'Not disclosed'}")
    print(f"    - Allowed Methods: {cors_results['allow_methods'] or 'Not disclosed'}")

    if cors_results["findings"]:
        print("    - Findings:")
        for finding in cors_results["findings"]:
            print(f"        [!] {finding}")
    else:
        print("    - No CORS security issues detected")

    print("\n[+] robots.txt Analysis")

    print(f"    - Status: {robots_results['status']}")
    print(f"    - URL: {robots_results['robots_url']}")

    if robots_results["status"] == "found":
        print(
            f"    - Disallowed Paths: "
            f"{robots_results['disallowed_count']}"
        )

        if robots_results["disallowed_paths"]:
            print("    - Paths:")
            for path in robots_results["disallowed_paths"]:
                print(f"        [i] {path}")

    elif robots_results["status"] == "error":
        print(f"    - Error: {robots_results.get('error')}")