from cors import analyze_cors


# Test 1: Secure CORS configuration
result = analyze_cors({
    "Access-Control-Allow-Origin": "https://example.com",
    "Access-Control-Allow-Credentials": "false",
    "Access-Control-Allow-Methods": "GET, POST"
})

assert result["status"] == "secure"
assert len(result["findings"]) == 0


# Test 2: Wildcard origin
result = analyze_cors({
    "Access-Control-Allow-Origin": "*"
})

assert result["status"] == "warning"
assert "Wildcard Access-Control-Allow-Origin (*) is enabled" in result["findings"]


# Test 3: Wildcard origin with credentials
result = analyze_cors({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Credentials": "true"
})

assert result["status"] == "warning"
assert "Wildcard CORS origin is used with credentials enabled" in result["findings"]


print("All CORS tests passed!")