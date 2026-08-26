import requests
from urllib.parse import urlparse


def analyze_robots(url, timeout=10):
    parsed_url = urlparse(url)
    robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"

    try:
        response = requests.get(robots_url, timeout=timeout)

        if response.status_code == 404:
            return {
                "status": "not_found",
                "robots_url": robots_url,
                "findings": ["robots.txt file was not found"]
            }

        if response.status_code != 200:
            return {
                "status": "error",
                "robots_url": robots_url,
                "findings": [
                    f"robots.txt returned HTTP {response.status_code}"
                ]
            }

        lines = response.text.splitlines()

        disallowed_paths = []

        for line in lines:
            line = line.strip()

            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()

                if path:
                    disallowed_paths.append(path)

        return {
            "status": "found",
            "robots_url": robots_url,
            "disallowed_paths": disallowed_paths,
            "disallowed_count": len(disallowed_paths)
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "robots_url": robots_url,
            "error": str(error)
        }