import argparse
import json

from cli import print_scan_result
from reporter import (
    generate_html_report,
    generate_json_report,
)
from scan_engine import run_security_scan
from url_utils import normalize_url
from logger_config import configure_logging


parser = argparse.ArgumentParser(
    description="Web Security Scanner"
)


parser.add_argument(
    "url",
    help="Target URL"
)


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

configure_logging()


# Normalize and validate the target URL
try:
    target_url = normalize_url(args.url)

except ValueError as error:
    print(f"[-] Invalid URL: {error}")
    exit(1)


# Run the complete security scan
final_results = run_security_scan(
    target_url,
    args.method,
    args.timeout,
)


# Stop if the initial scan request failed
if "error" in final_results:
    print(
        "[-] Request failed:",
        final_results["error"],
    )
    exit(1)


# Display complete results as JSON
if args.json:
    print(
        json.dumps(
            final_results,
            indent=4,
        )
    )
    exit()


# Display scan results in the terminal
print_scan_result(final_results)


# Save JSON report
if args.output:
    try:
        generate_json_report(
            final_results,
            args.output,
        )

        print(
            f"\n[+] JSON report saved to: "
            f"{args.output}"
        )

    except OSError as error:
        print(
            f"\n[-] Failed to save JSON report: "
            f"{error}"
        )


# Save HTML report
if args.html:
    try:
        generate_html_report(
            final_results,
            args.html,
        )

        print(
            f"\n[+] HTML report saved to: "
            f"{args.html}"
        )

    except OSError as error:
        print(
            f"\n[-] Failed to save HTML report: "
            f"{error}"
        )