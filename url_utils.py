from urllib.parse import urlparse


def normalize_url(url):
    """
    Validate and normalize a target URL.

    If the user does not provide a scheme,
    HTTPS is used by default.
    """

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty")

    # Add HTTPS when no scheme is provided
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    # Make sure a hostname exists
    if not parsed.netloc:
        raise ValueError("Invalid URL")

    # Only allow HTTP and HTTPS
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            "Unsupported URL scheme. Use HTTP or HTTPS."
        )

    return url