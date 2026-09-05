from scanner import scan_url
from headers import check_security_headers
from cookies import check_cookie_security
from tls import analyze_tls
from redirects import analyze_redirects
from methods import analyze_methods
from technology import analyze_technology
from disclosure import analyze_information_disclosure
from cors import analyze_cors
from robots import analyze_robots
from endpoints import check_common_endpoints
from scoring import calculate_score

from urllib.parse import urlparse


def run_security_scan(url, method="GET", timeout=10):
    """
    Run the complete web security scanning pipeline.
    """

    # Step 1: Perform the main HTTP scan
    result = scan_url(url, method, timeout)

    # Stop immediately if the main scan fails
    if "error" in result:
        return result

    # Step 2: Run all security analysis modules
    security_headers = check_security_headers(result["headers"])
    cookies = check_cookie_security(result["headers"])
    redirect_results = analyze_redirects(result)

    method_results = analyze_methods(
        result["url"],
        timeout
    )

    technology_results = analyze_technology(result["headers"])
    disclosure_results = analyze_information_disclosure(
        result["headers"]
    )
    cors_results = analyze_cors(result["headers"])

    robots_results = analyze_robots(
        result["url"],
        timeout
    )

    endpoint_results = check_common_endpoints(
        result["url"]
    )

    # Step 3: Analyze TLS when HTTPS is being used
    parsed_url = urlparse(result["url"])
    tls_results = {}

    if parsed_url.scheme == "https":
        tls_results = analyze_tls(
            parsed_url.hostname
        )

    # Step 4: Normalize cookie results
    cookie_results = {
        "status": (
            "Cookies analyzed"
            if cookies
            else "No cookies found"
        ),
        "cookies": cookies,
    }

    # Step 5: Build ONE canonical report
    report = {
        "target_info": {
            "url": result["url"],
            "method": result["method"],
            "status_code": result["status_code"],
            "server": result["server"],
            "content_type": result["content_type"],
            "redirects": result["redirects"],
            "response_size": result["response_size"],
        },

        "security_headers": security_headers,
        "cookies": cookie_results,
        "tls": tls_results,
        "redirects": redirect_results,
        "methods": method_results,
        "technology": technology_results,
        "information_disclosure": disclosure_results,
        "cors": cors_results,
        "robots": robots_results,
        "endpoints": endpoint_results,
    }

    # Step 6: Calculate the score directly from the report
    scoring_input = {
        **report,
        "basic": {
            "url": report["target_info"]["url"]
        }
    }

    report["security_score"] = calculate_score(
        scoring_input
    )

    return report