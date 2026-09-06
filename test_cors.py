from cors import analyze_cors


def test_secure_cors_configuration():
    result = analyze_cors({
        "Access-Control-Allow-Origin": "https://example.com",
        "Access-Control-Allow-Credentials": "false",
        "Access-Control-Allow-Methods": "GET, POST",
    })

    assert result["status"] == "secure"
    assert len(result["findings"]) == 0


def test_wildcard_origin():
    result = analyze_cors({
        "Access-Control-Allow-Origin": "*"
    })

    assert result["status"] == "warning"
    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert finding["name"] == "Wildcard CORS Origin"
    assert finding["severity"] == "Medium"
    assert (
        finding["description"]
        == "Wildcard Access-Control-Allow-Origin (*) is enabled"
    )


def test_wildcard_origin_with_credentials():
    result = analyze_cors({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })

    assert result["status"] == "warning"
    assert len(result["findings"]) == 2

    first_finding = result["findings"][0]
    second_finding = result["findings"][1]

    assert first_finding["name"] == "Wildcard CORS Origin"

    assert second_finding["name"] == (
        "Wildcard CORS With Credentials"
    )
    assert second_finding["severity"] == "High"
    assert (
        second_finding["description"]
        == "Wildcard CORS origin is used with credentials enabled"
    )