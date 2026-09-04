from urllib.parse import urlparse

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


def run_security_scan(url, method="GET", timeout=10):
    # Main HTTP scan
    result = scan_url(url, method, timeout)

    # Stop immediately if the main scan failed
    if "error" in result:
        return result

    headers = result.get("headers", {})

    # Run all security analysis modules
    security_headers = check_security_headers(headers)

    cookies = check_cookie_security(headers)

    redirect_results = analyze_redirects(result)

    method_results = analyze_methods(
        result["url"],
        timeout
    )

    technology_results = analyze_technology(headers)

    disclosure_results = analyze_information_disclosure(headers)

    cors_results = analyze_cors(headers)

    robots_results = analyze_robots(
        result["url"],
        timeout
    )

    endpoint_results = check_common_endpoints(
        result["url"]
    )

    # Parse the target URL
    parsed_url = urlparse(result["url"])

    # TLS analysis only makes sense for HTTPS
    tls_analysis = {}

    if parsed_url.scheme == "https":
        tls_analysis = analyze_tls(
            parsed_url.hostname
        )

    # Prepare data specifically for the scoring engine
    scoring_input = {
        "basic": {
            "url": result["url"]
        },

        "security_headers": security_headers,

        "tls": tls_analysis,

        "methods": method_results,

        "cookies": {
            "status": (
                "Cookies analyzed"
                if cookies
                else "No cookies found"
            ),
            "cookies": cookies
        },

        "redirects": redirect_results,

        "information_disclosure": disclosure_results
    }

    # Calculate final security score
    score_results = calculate_score(
        scoring_input
    )

    # Return the complete security report
    return {
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

        "cookies": {
            "status": (
                "Cookies analyzed"
                if cookies
                else "No cookies found"
            ),
            "cookies": cookies
        },

        "tls_analysis": tls_analysis,

        "redirect_analysis": redirect_results,

        "method_analysis": method_results,

        "technology_analysis": technology_results,

        "information_disclosure": disclosure_results,

        "cors_analysis": cors_results,

        "robots_analysis": robots_results,

        "endpoint_analysis": endpoint_results,

        "security_score": score_results
    }