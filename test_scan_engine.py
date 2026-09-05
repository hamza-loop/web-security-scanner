from unittest.mock import patch, Mock
from scan_engine import run_security_scan


def test_scan_engine_returns_error_when_scan_fails():
    fake_result = {
        "error": "Connection failed"
    }

    # If calculate_score is called when a scan fails, you must patch it here.
    # If it is NOT called when a scan fails, you should remove this patch entirely.
    with patch("scan_engine.scan_url", return_value=fake_result), \
         patch("scan_engine.calculate_score") as mock_calculate_score:
         
        result = run_security_scan("https://example.com")

    assert result == fake_result
    # mock_calculate_score.assert_called_once() # Uncomment if it's supposed to be called


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

    # Defined locally inside this test so it is in scope
    mock_calculate_score = Mock(
        return_value={
            "score": 100,
            "risk_level": "Low Risk"
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
        mock_calculate_score  # Now this variable safely exists in this scope
    ):
        result = run_security_scan("https://example.com")

    assert result["target_info"]["url"] == "https://example.com/"
    assert result["target_info"]["status_code"] == 200
    assert result["security_score"]["score"] == 100

    mock_calculate_score.assert_called_once()

    scoring_input = mock_calculate_score.call_args[0][0]

    assert scoring_input["target_info"]["url"] == (
        "https://example.com/"
    )

    assert scoring_input["basic"] == {
        "url": "https://example.com/"
    }

    assert scoring_input["security_headers"] == {}

    assert scoring_input["tls"] == {
        "certificate_valid": True,
        "hostname_valid": True
    }

    assert scoring_input["cookies"] == {
        "status": "No cookies found",
        "cookies": []
    }

    assert scoring_input["redirects"] == {}
    assert scoring_input["methods"] == {
        "status": "success",
        "allowed_methods": []
    }

    assert scoring_input["information_disclosure"] == {}
    mock_methods.assert_called_once_with(
        "https://example.com/",
        10
    )