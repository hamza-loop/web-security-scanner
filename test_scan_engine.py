from unittest.mock import patch, Mock
from scan_engine import run_security_scan


def test_scan_engine_returns_error_when_scan_fails():
    fake_result = {
        "error": "Connection failed"
    }

    with patch("scan_engine.scan_url", return_value=fake_result):
        result = run_security_scan("https://example.com")

    assert result == fake_result


def test_scan_engine_returns_complete_results():
    fake_scan_result = {
        "url": "https://example.com/",
        "method": "GET",
        "status_code": 200,
        "headers": {},
        "server": "ExampleServer",
        "content_type": "text/html",
        "redirects": 0,
        "response_size": 100,
    }

    mock_methods = Mock(
        return_value={
            "status": "success",
            "allowed_methods": []
        }
    )

    with patch(
        "scan_engine.scan_url",
        return_value=fake_scan_result
    ), patch(
        "scan_engine.check_security_headers",
        return_value={}
    ), patch(
        "scan_engine.check_cookie_security",
        return_value=[]
    ), patch(
        "scan_engine.analyze_redirects",
        return_value={}
    ), patch(
        "scan_engine.analyze_methods",
        mock_methods
    ), patch(
        "scan_engine.analyze_technology",
        return_value={}
    ), patch(
        "scan_engine.analyze_information_disclosure",
        return_value={}
    ), patch(
        "scan_engine.analyze_cors",
        return_value={}
    ), patch(
        "scan_engine.analyze_robots",
        return_value={}
    ), patch(
        "scan_engine.check_common_endpoints",
        return_value=[]
    ), patch(
        "scan_engine.analyze_tls",
        return_value={
            "certificate_valid": True,
            "hostname_valid": True
        }
    ), patch(
        "scan_engine.calculate_score",
        return_value={
            "score": 100,
            "risk_level": "Low Risk"
        }
    ):
        result = run_security_scan("https://example.com")

    assert result["target_info"]["url"] == "https://example.com/"
    assert result["target_info"]["status_code"] == 200
    assert result["security_score"]["score"] == 100

    mock_methods.assert_called_once_with(
        "https://example.com/",
        10
    )
