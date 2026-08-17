import argparse
from scanner import scan_url

parser = argparse.ArgumentParser(description="Web Security Scanner")

parser.add_argument("url", help="Target URL")

parser.add_argument(
    "--method",
    choices=["GET", "HEAD"],
    default="GET",
    help="HTTP method to use"
)

args = parser.parse_args()

result = scan_url(args.url, args.method)

print(result)

