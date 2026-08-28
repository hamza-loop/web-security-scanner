from cors import analyze_cors


def test_secure_cors_configuration():
    result = analyze_cors({
        "Access-Control-Allow-Origin": "https://example.com",
        "Access-Control-Allow-Credentials": "false",
        "Access-Control-Allow-Methods": "GET, POST"
    })

    assert result["status"] == "secure"
    assert len(result["findings"]) == 0


def test_wildcard_origin():
    result = analyze_cors({
        "Access-Control-Allow-Origin": "*"
    })

    assert result["status"] == "warning"
    assert (
        "Wildcard Access-Control-Allow-Origin (*) is enabled"
        in result["findings"]
    )


def test_wildcard_origin_with_credentials():
    result = analyze_cors({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"
    })

    assert result["status"] == "warning"
    assert (
        "Wildcard CORS origin is used with credentials enabled"
        in result["findings"]
    )