import argparse
from scanner import scan_url

parser = argparse.ArgumentParser(description="Web Security Scanner")
parser.add_argument("url", help="Target URL")
parser.add_argument("--method", choices=["GET", "HEAD"], default="GET", help="HTTP method to use")
parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")

args = parser.parse_args()

result = scan_url(
    args.url,
    args.method,
    args.timeout
)

if "error" in result:
    print("[-] Request failed:", result["error"])
else:
    print("\n[+] Scan Result")
    print("    - URL:", result["url"])
    print("    - Method:", result["method"])
    print("    - Status:", result["status_code"])
    print("    - Server:", result["server"])
    print("    - Content Type:", result["content_type"])
    print("    - Redirects:", result["redirects"])
    print("    - Response Size:", result["response_size"])