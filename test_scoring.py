from scoring import calculate_score


mock_scan = {
    "security_headers": {
        "HSTS": {
            "status": "Missing",
            "value": None
        },
        "CSP": {
            "status": "Missing",
            "value": None
        },
        "X-Content-Type-Options": {
            "status": "Present",
            "value": "nosniff"
        },
        "X-Frame-Options": {
            "status": "Missing",
            "value": None
        }
    },

    "tls": {
        "is_https": True,
        "certificate_valid": False,
        "hostname_valid": True
    },

    "methods": {
        "allowed_methods": ["GET", "POST", "TRACE"]
    },

    "cookies": {
        "status": "Cookies found",
        "cookies": [
            {
                "name": "session_id",
                "secure": False,
                "httponly": False,
                "samesite": None
            }
        ]
    },

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
        "security_headers": {
        "HSTS": {
            "status": "Missing",
            "value": None
        },
        "CSP": {
            "status": "Missing",
            "value": None
        },
        "X-Content-Type-Options": {
            "status": "Present",
            "value": "nosniff"
        },
        "X-Frame-Options": {
            "status": "Present",
            "value": "SAMEORIGIN"
        }
    },

    "tls": {
        "is_https": True,
        "certificate_valid": True,
        "hostname_valid": True,
    },

    "methods": {
        "allowed_methods": [],
    },

    "cookies": {
        "status": "No cookies found",
        "cookies": []
    },

    "redirects": {
        "security_status": "Secure",
    },

    "information_disclosure": {
        "findings": [],
    },
}

    result = calculate_score(scan_data)

    assert result["score"] == 70
    