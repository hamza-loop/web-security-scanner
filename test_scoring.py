from scoring import calculate_score


mock_scan = {
    "headers": {
        "HSTS": False,
        "CSP": False,
        "X-Content-Type-Options": True,
        "X-Frame-Options": False
    },
    "tls": {
        "is_https": True,
        "valid_certificate": False,
        "valid_hostname": True
    },
    "methods": {
        "allowed_methods": ["GET", "POST", "TRACE"]
    },
    "cookies": [
        {
            "name": "session_id",
            "secure": False,
            "httponly": False,
            "samesite": None
        }
    ],
    "redirects": {
        "security_status": "Warning"
    },
    "information_disclosure": {
        "findings": [
            "Server exposes version information: Apache/2.4.57"
        ]
    }
}


result = calculate_score(mock_scan)

print("=== SECURITY RATING ===")
print(f"Overall Score: {result['score']}/100")
print(f"Risk Level:    {result['risk_level']}")

print("\nPositive Security Findings:")
for finding in result["positive_findings"]:
    print(f"[+] {finding}")

print("\nDetailed Deductions:")
for finding in result["findings"]:
    print(f"[-] {finding}")

def test_calculate_score_returns_expected_score():
    result = calculate_score(mock_scan)

    assert result["score"] >= 0
    assert result["score"] <= 100

def test_score_deductions_for_missing_headers():
    scan_data = {
        "headers": {
            "HSTS": False,
            "CSP": False,
            "X-Content-Type-Options": True,
            "X-Frame-Options": True,
        },
        "tls": {
            "is_https": True,
            "valid_certificate": True,
            "valid_hostname": True,
        },
        "methods": {
            "allowed_methods": [],
        },
        "cookies": [],
        "redirects": {
            "security_status": "Secure",
        },
        "information_disclosure": {
            "findings": [],
        },
    }

    result = calculate_score(scan_data)

    assert result["score"] == 70
    