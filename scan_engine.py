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
    result = scan_url(url, method, timeout)

    if "error" in result:
        return result

    security_headers = check_security_headers(result["headers"])
    cookies = check_cookie_security(result["headers"])
    redirect_results = analyze_redirects(result)
    method_results = analyze_methods(result["url"], timeout)
    technology_results = analyze_technology(result["headers"])
    disclosure_results = analyze_information_disclosure(result["headers"])
    cors_results = analyze_cors(result["headers"])

    robots_results = analyze_robots(result["url"], timeout)
    endpoint_results = check_common_endpoints(result["url"])

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
            ),
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
            ),
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
        "information_disclosure": disclosure_results,
    }

    score_results = calculate_score(scoring_input)

    return {
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
        "cookies": cookies,
        "tls_analysis": tls_analysis,
        "redirect_analysis": redirect_results,
        "method_analysis": method_results,
        "technology_analysis": technology_results,
        "information_disclosure": disclosure_results,
        "cors_analysis": cors_results,
        "robots_analysis": robots_results,
        "security_score": score_results,
        "endpoint_analysis": endpoint_results,
    }
