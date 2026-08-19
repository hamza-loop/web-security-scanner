import argparse

from scanner import scan_url
from headers import check_security_headers
from cookies import check_cookie_security


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

    print("\n[+] Scan Result")

    print("    - URL:", result["url"])
    print("    - Method:", result["method"])
    print("    - Status:", result["status_code"])
    print("    - Server:", result["server"])
    print("    - Content Type:", result["content_type"])
    print("    - Redirects:", result["redirects"])
    print("    - Response Size:", result["response_size"])

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