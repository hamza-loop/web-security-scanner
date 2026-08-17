import requests

def scan_url(url, method="GET"):
    try:
        response = requests.request(method, url, timeout=10)

        return {
            "url": response.url,
            "method": method,
            "status_code": response.status_code,
            "headers": dict(response.headers)
        }

    except requests.RequestException as error:
        return {
            "url": url,
            "method": method,
            "error": str(error)
        }

if __name__ == "__main__":
    result = scan_url("https://example.com", "HEAD")
    print(result)