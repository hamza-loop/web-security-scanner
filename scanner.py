import requests

def scan_url(url, method="GET", timeout=10):
    try:
        headers = {
            "User-Agent": "Hamza-Security-Scanner/1.0"
        }

        response = requests.request(method,url, headers=headers, timeout=timeout)

        return {
            "url": response.url,
            "method": method,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "unknown"),
            "content_type": response.headers.get("Content-Type", "unknown"),
            "redirects": len(response.history),
            "response_size": len(response.content),
            "headers": dict(response.headers)
        }

    except requests.RequestException as error:
        return {
            "url": url,
            "method": method,
            "error": str(error)
        }