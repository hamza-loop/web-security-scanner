from urllib.parse import urlparse


def analyze_redirects(result):
    redirects = result.get("redirect_history", [])

    original_url = redirects[0]["url"] if redirects else result["url"]

    original_scheme = urlparse(original_url).scheme
    final_scheme = urlparse(result["url"]).scheme

    schemes = [original_scheme]

    for redirect in redirects:
        schemes.append(urlparse(redirect["url"]).scheme)

    schemes.append(final_scheme)

    downgrade_detected = False

    for i in range(len(schemes) - 1):
        if schemes[i] == "https" and schemes[i + 1] == "http":
            downgrade_detected = True
            break

    if downgrade_detected:
        security_status = "Warning"
    elif len(redirects) == 0:
        security_status = "No Redirects"
    elif original_scheme == "http" and final_scheme == "https":
        security_status = "Secure Upgrade"
    else:
        security_status = "No Downgrade"

    return {
        "redirect_count": len(redirects),
        "final_url": result["url"],
        "original_scheme": original_scheme,
        "final_scheme": final_scheme,
        "security_status": security_status,
        "redirects": redirects
    }