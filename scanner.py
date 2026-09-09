import requests
import logging


logger = logging.getLogger(__name__)

def scan_url(url, method="GET", timeout=10):
    try:
        headers = {"User-Agent": "Hamza-Security-Scanner/1.0"}
        logger.info("Sending %s request to %s", method, url)
        response = requests.request(method, url, headers=headers, timeout=timeout)
        logger.info("Received response with status code %s", response.status_code)
        return {
            "url": response.url,
            "method": method,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "unknown"),
            "content_type": response.headers.get("Content-Type", "unknown"),
            "redirects": len(response.history),
            "response_size": len(response.content),
            "headers": dict(response.headers),
            "redirect_history": [
                {
                    "status_code": redirect.status_code,
                    "url": redirect.url,
                    "location": redirect.headers.get("Location"),
                }
                for redirect in response.history
            ],
        }
    except requests.exceptions.Timeout:
        logger.warning("Request timed out for %s", url)
        return {
            "url": url,
            "method": method,
            "error_type": "timeout",
            "error": "Connection timed out",
        }
    except requests.exceptions.ConnectionError as error:
        logger.error("Connection error while scanning %s", url)
        error_message = str(error)
        if "NameResolutionError" in error_message:
            error_type = "dns"
            message = "Could not resolve hostname"
        else:
            error_type = "connection"
            message = "Could not connect to target"
        return {
            "url": url,
            "method": method,
            "error_type": error_type,
            "error": message,
        }
    except requests.exceptions.RequestException as error:
        logger.error("Request failed for %s: %s", url, error)
        return {
            "url": url,
            "method": method,
            "error_type": "request",
            "error": str(error),
        }
