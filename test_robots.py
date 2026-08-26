from robots import analyze_robots


result = analyze_robots("https://httpbin.org")

assert "status" in result
assert "robots_url" in result

print("All robots.txt tests passed!")