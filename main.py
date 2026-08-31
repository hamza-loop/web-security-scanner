import argparse
import json

from scan_engine import run_security_scan
from reporter import generate_html_report
from url_utils import normalize_url


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

try:
    target_url = normalize_url(args.url)
except ValueError as error:
    print(f"[-] Invalid URL: {error}")
    exit(1)


# Run the complete security scan
final_results = run_security_scan(
    target_url,
    args.method,
    args.timeout
)


# Stop if the initial scan request failed
if "error" in final_results:
    print("[-] Request failed:", final_results["error"])
    exit()


# Extract results for terminal display
result = final_results["target_info"]
security_headers = final_results["security_headers"]
cookies = final_results["cookies"]
tls_analysis = final_results["tls_analysis"]
redirect_results = final_results["redirect_analysis"]
method_results = final_results["method_analysis"]
technology_results = final_results["technology_analysis"]
disclosure_results = final_results["information_disclosure"]
cors_results = final_results["cors_analysis"]
robots_results = final_results["robots_analysis"]
endpoint_results = final_results["endpoint_analysis"]
score_results = final_results["security_score"]


# JSON output
if args.json:
    print(json.dumps(final_results, indent=4))
    exit()


# Basic scan information
print("\n[+] Scan Result")
print("    - URL:", result["url"])
print("    - Method:", result["method"])
print("    - Status:", result["status_code"])
print("    - Server:", result["server"])
print("    - Content Type:", result["content_type"])
print("    - Redirects:", result["redirects"])
print("    - Response Size:", result["response_size"])


# Security score
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


# Redirect security
print("\n[+] Redirect Security")
print(f"    - Redirect Count: {redirect_results.get('redirect_count')}")
print(f"    - Original Scheme: {redirect_results.get('original_scheme')}")
print(f"    - Final Scheme: {redirect_results.get('final_scheme')}")
print(f"    - Security Status: {redirect_results.get('security_status')}")


# Security headers
print("\n[+] Security Headers")

for header, details in security_headers.items():
    print(f"    - {header}: {details['status']}")


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
    for method, details in method_results["method_tests"].items():
        status = "Allowed" if details["allowed"] else "Blocked"
        print(f"        {method}: {details['status_code']} ({status})")
else:
    print(f"    - Status: {method_results['status']}")
    print(f"    - Error: {method_results['error']}")


# Cookie security
print("\n[+] Cookie Security")

if cookies:
    for cookie in cookies:
        print(f"    - {cookie['name']}:")
        print(f"        Secure: {'Present' if cookie['secure'] else 'Missing'}")
        print(
            f"        HttpOnly: "
            f"{'Present' if cookie['httponly'] else 'Missing'}"
        )
        print(f"        SameSite: {cookie['samesite'] or 'Missing'}")
else:
    print("    - No cookies found")


# TLS security
if tls_analysis:
    print("\n[+] TLS Security")

    if tls_analysis["status"] == "success":
        print(f"    - TLS Version: {tls_analysis['tls_version']}")
        print(
            f"    - Certificate Valid: "
            f"{tls_analysis['certificate_valid']}"
        )
        print(
            f"    - Hostname Valid: "
            f"{tls_analysis['hostname_valid']}"
        )
        print(f"    - Valid Until: {tls_analysis['valid_until']}")
    else:
        print(f"    - Status: {tls_analysis['status']}")
        print(f"    - Error Type: {tls_analysis['error_type']}")
        print(f"    - Error: {tls_analysis['error']}")


# Technology detection
print("\n[+] Technology Detection")
print(f"    - Status: {technology_results['status']}")
print(
    f"    - Technologies Found: "
    f"{technology_results['technology_count']}"
)

if technology_results["technologies"]:
    for technology in technology_results["technologies"]:
        print(f"        - {technology['source']}: {technology['value']}")
else:
    print("        No technology information identified")


# Information disclosure
print("\n[+] Information Disclosure")
print(f"    - Status: {disclosure_results['status']}")

if disclosure_results["findings"]:
    print("    - Findings:")
    for finding in disclosure_results["findings"]:
        print(f"        [!] {finding}")
else:
    print("    - No unnecessary technology information disclosed")


# CORS security
print("\n[+] CORS Security")
print(f"    - Status: {cors_results['status']}")
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
    print("    - No CORS security issues detected")


# robots.txt analysis
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


# Common endpoint discovery
print("\n[+] Common Endpoint Discovery")

reachable_endpoints = [
    endpoint
    for endpoint in endpoint_results
    if endpoint["reachable"]
]

print(f"    - Reachable Endpoints: {len(reachable_endpoints)}")

if reachable_endpoints:
    for endpoint in reachable_endpoints:
        print(
            f"        [i] {endpoint['endpoint']} "
            f"({endpoint['status_code']})"
        )
else:
    print("    - No common endpoints found")


# Save JSON report
if args.output:
    try:
        with open(args.output, "w") as file:
            json.dump(final_results, file, indent=4)

        print(f"\n[+] Report saved to: {args.output}")

    except OSError as error:
        print(f"\n[-] Failed to save report: {error}")


# Save HTML report
if args.html:
    try:
        generate_html_report(final_results, args.html)
        print(f"\n[+] HTML report saved to: {args.html}")

    except OSError as error:
        print(f"\n[-] Failed to save HTML report: {error}")