import requests
from urllib.parse import urljoin


COMMON_ENDPOINTS = [
    "/admin",
    "/login",
    "/api",
    "/dashboard",
    "/sitemap.xml",
]


def check_common_endpoints(url):
    """Check common public endpoints on a target website."""
    
    results = []

    for endpoint in COMMON_ENDPOINTS:
        endpoint_url = urljoin(url, endpoint)

        try:
            response = requests.get(
                endpoint_url,
                timeout=5,
                allow_redirects=False
            )

            results.append({
                "endpoint": endpoint,
                "url": endpoint_url,
                "status_code": response.status_code,
                "reachable": response.status_code < 400
            })

        except requests.RequestException as error:
            results.append({
                "endpoint": endpoint,
                "url": endpoint_url,
                "status_code": None,
                "reachable": False,
                "error": str(error)
            })

    return results
