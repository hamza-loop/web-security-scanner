import requests
from unittest.mock import Mock, patch
from endpoints import check_common_endpoints


@patch("endpoints.requests.get")
def test_common_endpoints_found(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_get.return_value = mock_response

    results = check_common_endpoints("https://example.com")

    assert len(results) == 5

    for result in results:
        assert result["reachable"] is True
        assert result["status_code"] == 200


@patch("endpoints.requests.get")
def test_common_endpoints_not_found(mock_get):
    mock_response = Mock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    results = check_common_endpoints("https://example.com")

    for result in results:
        assert result["reachable"] is False
        assert result["status_code"] == 404



@patch("endpoints.requests.get")
def test_common_endpoints_request_error(mock_get):
    mock_get.side_effect = requests.RequestException("Connection failed")

    results = check_common_endpoints("https://example.com")

    assert len(results) == 5

    for result in results:
        assert result["reachable"] is False
        assert result["status_code"] is None
        assert "Connection failed" in result["error"]
