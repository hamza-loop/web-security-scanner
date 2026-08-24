def analyze_technology(headers):
    technologies = []

    technology_headers = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version"
    ]

    for header in technology_headers:
        value = headers.get(header)

        if value:
            technologies.append({
                "source": header,
                "value": value
            })

    if technologies:
        status = "identified"
    else:
        status = "not_identified"

    return {
        "status": status,
        "technology_count": len(technologies),
        "technologies": technologies
    }
