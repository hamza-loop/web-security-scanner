def check_cookie_security(headers):
    results = []

    cookies = headers.get("Set-Cookie")

    if not cookies:
        return results

    if isinstance(cookies, str):
        cookies = [cookies]

    for cookie in cookies:
        parts = [part.strip() for part in cookie.split(";")]
        name = parts[0].split("=", 1)[0]

        attributes = {
            part.split("=", 1)[0].lower(): part.split("=", 1)[1]
            if "=" in part
            else True
            for part in parts[1:]
        }

        results.append({
            "name": name,
            "secure": "secure" in attributes,
            "httponly": "httponly" in attributes,
            "samesite": attributes.get("samesite")
        })

    return results
