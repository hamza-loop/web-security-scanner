import argparse
from urllib.parse import urlparse

from scanner import scan_url
from headers import check_security_headers
from cookies import check_cookie_security
from tls import analyze_tls
from redirects import analyze_redirects


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

    parsed_url = urlparse(result["url"])
    tls_analysis = None

    if parsed_url.scheme == "https":
        tls_analysis = analyze_tls(parsed_url.hostname)

    print("\n[+] Scan Result")

    print("    - URL:", result["url"])
    print("    - Method:", result["method"])
    print("    - Status:", result["status_code"])
    print("    - Server:", result["server"])
    print("    - Content Type:", result["content_type"])
    print("    - Redirects:", result["redirects"])
    print("    - Response Size:", result["response_size"])

    print("\n[+] Redirect Security")
    print(f"    - Redirect Count: {redirect_results.get('redirect_count')}")
    print(f"    - Original Scheme: {redirect_results.get('original_scheme')}")
    print(f"    - Final Scheme: {redirect_results.get('final_scheme')}")
    print(f"    - Security Status: {redirect_results.get('security_status')}")

    print("\n[+] Security Headers")

    for header, details in security_headers.items():
        print(f"    - {header}: {details['status']}")

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