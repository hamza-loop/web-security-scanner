SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options"
}


def check_security_headers(headers):
    results = {}

    for header, name in SECURITY_HEADERS.items():
        value = headers.get(header)

        results[name] = {
            "status": "Present" if value else "Missing",
            "value": value
        }

    return results

