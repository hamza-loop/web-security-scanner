from async_scanner import run_async_scan


def test_async_scan():
    urls = [
        "https://example.com",
        "https://httpbin.org/status/200",
        "https://httpbin.org/status/404",
    ]

    results = run_async_scan(
        urls,
        max_concurrent_requests=2
    )

    assert len(results) == 3

    assert results[0]["url"] == "https://example.com"
    assert results[0]["status"] == 200

    assert results[1]["url"] == "https://httpbin.org/status/200"
    assert results[1]["status"] == 200

    assert results[2]["url"] == "https://httpbin.org/status/404"
    assert results[2]["status"] == 404