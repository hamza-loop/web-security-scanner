import pytest

from cookies import check_cookie_security
from cors import analyze_cors
from disclosure import analyze_information_disclosure
from headers import check_security_headers
from redirects import analyze_redirects
from technology import analyze_technology


# ---------------------------------------------------------------------------
# headers.py
# ---------------------------------------------------------------------------

def test_all_security_headers_present():
    result = check_security_headers({
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    })
    assert all(item["status"] == "Present" for item in result.values())


def test_all_security_headers_missing():
    result = check_security_headers({})
    assert set(result) == {"HSTS", "CSP", "X-Content-Type-Options", "X-Frame-Options"}
    assert all(item["status"] == "Missing" for item in result.values())
    assert all(item["value"] is None for item in result.values())


def test_header_value_is_returned_unchanged():
    result = check_security_headers({"X-Frame-Options": "SAMEORIGIN"})
    assert result["X-Frame-Options"] == {"status": "Present", "value": "SAMEORIGIN"}


def test_empty_header_value_counts_as_missing():
    result = check_security_headers({"Content-Security-Policy": ""})
    assert result["CSP"]["status"] == "Missing"


def test_only_one_header_present():
    result = check_security_headers({"Strict-Transport-Security": "max-age=1"})
    assert result["HSTS"]["status"] == "Present"
    assert result["CSP"]["status"] == "Missing"


# ---------------------------------------------------------------------------
# cookies.py
# ---------------------------------------------------------------------------

def test_no_set_cookie_header_returns_empty_list():
    assert check_cookie_security({}) == []


def test_cookie_with_all_attributes():
    cookies = check_cookie_security(
        {"Set-Cookie": "sid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"}
    )
    assert cookies == [
        {"name": "sid", "secure": True, "httponly": True, "samesite": "Strict"}
    ]


def test_cookie_without_attributes_is_flagged_insecure():
    cookie = check_cookie_security({"Set-Cookie": "sid=abc123"})[0]
    assert cookie["secure"] is False
    assert cookie["httponly"] is False
    assert cookie["samesite"] is None


def test_cookie_attribute_names_are_case_insensitive():
    cookie = check_cookie_security({"Set-Cookie": "sid=1; SECURE; httponly"})[0]
    assert cookie["secure"] is True
    assert cookie["httponly"] is True


def test_multiple_cookies_supplied_as_a_list():
    cookies = check_cookie_security(
        {"Set-Cookie": ["a=1; Secure", "b=2; HttpOnly; SameSite=Lax"]}
    )
    assert [c["name"] for c in cookies] == ["a", "b"]
    assert cookies[0]["secure"] is True
    assert cookies[1]["samesite"] == "Lax"


def test_cookie_value_containing_equals_sign_keeps_correct_name():
    cookie = check_cookie_security({"Set-Cookie": "token=a=b=c; Secure"})[0]
    assert cookie["name"] == "token"


# ---------------------------------------------------------------------------
# cors.py (adds to the existing test_cors.py)
# ---------------------------------------------------------------------------

def test_cors_without_any_headers_is_secure():
    result = analyze_cors({})
    assert result["status"] == "secure"
    assert result["allow_origin"] is None
    assert result["findings"] == []


def test_cors_credentials_check_is_case_insensitive():
    result = analyze_cors({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "TRUE",
    })
    assert len(result["findings"]) == 2


def test_cors_credentials_with_specific_origin_is_not_flagged():
    result = analyze_cors({
        "Access-Control-Allow-Origin": "https://app.example.com",
        "Access-Control-Allow-Credentials": "true",
    })
    assert result["status"] == "secure"


def test_cors_returns_allowed_methods_unchanged():
    result = analyze_cors({"Access-Control-Allow-Methods": "GET, POST"})
    assert result["allow_methods"] == "GET, POST"


# ---------------------------------------------------------------------------
# disclosure.py
# ---------------------------------------------------------------------------

def test_no_sensitive_headers_is_secure():
    result = analyze_information_disclosure({"Content-Type": "text/html"})
    assert result["status"] == "secure"
    assert result["exposed_headers"] == {}


def test_server_name_without_version_is_low_severity():
    finding = analyze_information_disclosure({"Server": "nginx"})["findings"][0]
    assert finding["severity"] == "Low"
    assert finding["name"] == "Technology Information Disclosure"


@pytest.mark.parametrize(
    "header, value",
    [
        ("Server", "Apache/2.4.41"),
        ("X-Powered-By", "PHP/7.4.3"),
        ("X-AspNet-Version", "4.0.30319"),
        ("X-AspNetMvc-Version", "5.2"),
    ],
)
def test_headers_with_version_numbers_are_medium_severity(header, value):
    result = analyze_information_disclosure({header: value})
    assert result["status"] == "warning"
    assert result["findings"][0]["severity"] == "Medium"
    assert result["exposed_headers"] == {header: value}


def test_multiple_disclosing_headers_produce_multiple_findings():
    result = analyze_information_disclosure(
        {"Server": "nginx", "X-Powered-By": "Express"}
    )
    assert len(result["findings"]) == 2


def test_empty_sensitive_header_is_ignored():
    assert analyze_information_disclosure({"Server": ""})["findings"] == []


# ---------------------------------------------------------------------------
# technology.py
# ---------------------------------------------------------------------------

def test_no_technology_headers_not_identified():
    result = analyze_technology({})
    assert result["status"] == "not_identified"
    assert result["technology_count"] == 0


def test_technologies_are_listed_with_their_source_header():
    result = analyze_technology({"Server": "nginx", "X-Powered-By": "Express"})
    assert result["status"] == "identified"
    assert result["technology_count"] == 2
    assert {"source": "Server", "value": "nginx"} in result["technologies"]


# ---------------------------------------------------------------------------
# redirects.py
# ---------------------------------------------------------------------------

def test_no_redirects():
    result = analyze_redirects({"url": "https://example.com/"})
    assert result["security_status"] == "No Redirects"
    assert result["redirect_count"] == 0


def test_http_to_https_redirect_is_a_secure_upgrade():
    result = analyze_redirects({
        "url": "https://example.com/",
        "redirect_history": [{"url": "http://example.com/"}],
    })
    assert result["security_status"] == "Secure Upgrade"
    assert result["original_scheme"] == "http"
    assert result["final_scheme"] == "https"


def test_https_to_http_redirect_is_flagged_as_downgrade():
    result = analyze_redirects({
        "url": "http://example.com/",
        "redirect_history": [{"url": "https://example.com/"}],
    })
    assert result["security_status"] == "Warning"


def test_https_to_https_redirect_has_no_downgrade():
    result = analyze_redirects({
        "url": "https://www.example.com/",
        "redirect_history": [{"url": "https://example.com/"}],
    })
    assert result["security_status"] == "No Downgrade"


def test_redirect_result_reports_count_and_final_url():
    history = [{"url": "http://a.com/"}, {"url": "https://a.com/"}]
    result = analyze_redirects({"url": "https://www.a.com/", "redirect_history": history})
    assert result["redirect_count"] == 2
    assert result["final_url"] == "https://www.a.com/"
    assert result["redirects"] == history