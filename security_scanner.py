from scanner import scan_url
from cookies import check_cookie_security
from tls import analyze_tls
from methods import analyze_methods
from cors import analyze_cors
from robots import analyze_robots
from endpoints import check_common_endpoints
from technology import analyze_technology
from disclosure import analyze_information_disclosure
from scoring import calculate_score


class SecurityScanner:

    def __init__(self, url, method="GET", timeout=10):
        self.url = url
        self.method = method
        self.timeout = timeout
        self.raw_results = None  # New: Keeps the unaltered network data pure
        self.results = None      # Stores the final processed nested report

    def scan(self):
        # Step 1: Perform the main network scan
        scan_results = scan_url(
            self.url,
            self.method,
            self.timeout
        )

        # If the main scan failed, store and return the error
        if "error" in scan_results:
            self.raw_results = scan_results
            self.results = scan_results
            return self.results

        # Step 2: Store the raw scan results cleanly
        self.raw_results = scan_results

        # Step 3: Build the complete security scan result using raw_results
        complete_results = {
            "basic_info": self.get_basic_info(),
            "headers": self.get_headers(),
            "redirects": self.get_redirects(),
            "security_headers": self.get_security_headers(),
            "cookies": self.get_cookie_security(),
            "tls": self.get_tls_security(),
            "methods": self.get_method_security(),
            "cors": self.get_cors_security(),
            "robots": self.get_robots_analysis(),
            "endpoints": self.get_endpoint_analysis(),
            "technology": self.get_technology_analysis(),
            "information_disclosure": self.get_information_disclosure()
        }

        # Step 4: Calculate the security score
        complete_results["security_score"] = calculate_score(complete_results)

        # Step 5: Store the complete results
        self.results = complete_results

        return self.results

    def get_basic_info(self):
        error = self._check_results()
        if error:
            return error
        
        # Updated: Read parameters from self.raw_results
        return {
            "url": self.raw_results.get("url"),
            "status_code": self.raw_results.get("status_code"),
            "server": self.raw_results.get("server"),
            "content_type": self.raw_results.get("content_type")
        }

    def get_headers(self):
        error = self._check_results()
        if error:
            return error

        # Updated: Read from self.raw_results
        return self.raw_results.get("headers", {})
    
    def get_redirects(self):
        error = self._check_results()
        if error:
            return error

        # Updated: Read from self.raw_results
        return {
            "redirects": self.raw_results.get("redirects", 0),
            "redirect_history": self.raw_results.get("redirect_history", [])
        }
    
    def get_security_headers(self):
        error = self._check_results()
        if error:
            return error

        # Updated: Read from self.raw_results
        headers = self.raw_results.get("headers", {})

        security_headers = {
            "HSTS": "Strict-Transport-Security",
            "CSP": "Content-Security-Policy",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "X-Frame-Options": "X-Frame-Options",
            "Referrer-Policy": "Referrer-Policy",
        }
    
        results = {}
        for name, header in security_headers.items():
            value = headers.get(header)
            if value:
                results[name] = {
                    "status": "Present",
                    "value": value
                }
            else:
                results[name] = {
                    "status": "Missing",
                    "value": None
                }

        return results
    
    def _check_results(self):
        # Updated: Check state via self.raw_results
        if self.raw_results is None:
            return {"error": "No scan results available. Run scan() first."}

        if "error" in self.raw_results:
            return self.raw_results

        return None
    
    def get_cookie_security(self):
        error = self._check_results()
        if error:
            return error

        # Updated: Read from self.raw_results
        headers = self.raw_results.get("headers", {})
        cookies = check_cookie_security(headers)

        if not cookies:
            return {
                "status": "No cookies found",
                "cookies": []
            }

        return {
            "status": "Cookies analyzed",
            "cookies": cookies
        }
    
    def get_tls_security(self):
        error = self._check_results()
        if error:
            return error

        # Updated: Extract original target URL directly from self.url property
        url = self.raw_results.get("url")
        if not url:
            return {
                "status": "error",
                "error": "Target URL is not available"
            }

        hostname = url.split("://")[-1].split("/")[0]
        return analyze_tls(hostname)
    
    def get_method_security(self):
        error = self._check_results()
        if error:
            return error

        # Updated: Extract original target URL directly from self.url property
        url = self.raw_results.get("url")
        if not url:
            return {
                "status": "error",
                "error": "Target URL is not available"
            }

        return analyze_methods(
            url,
            timeout=self.timeout
        )
    
    def get_cors_security(self):
        error = self._check_results()

        if error:
            return error

        headers = self.raw_results.get("headers", {})

        return analyze_cors(headers)
    
    def get_robots_analysis(self):
        error = self._check_results()

        if error:
            return error

        url = self.raw_results.get("url")

        if not url:
            return {
                "status": "error",
                "error": "Target URL is not available"
            }

        return analyze_robots(url, timeout=self.timeout)
    
    def get_endpoint_analysis(self):
        error = self._check_results()

        if error:
            return error

        url = self.raw_results.get("url")

        if not url:
            return {
                "status": "error",
                "error": "Target URL is not available"
            }

        return check_common_endpoints(url)
    
    def get_technology_analysis(self):
        error = self._check_results()

        if error:
            return error

        headers = self.raw_results.get("headers", {})

        return analyze_technology(headers)
    
    def get_information_disclosure(self):
        error = self._check_results()
        if error:
            return error

        headers = self.raw_results.get("headers", {})

        return analyze_information_disclosure(headers)


# --- Test Code ---

scanner = SecurityScanner("https://example.com")

# 1. Execute the network scan
scanner.scan()

# The methods below now safely pull from self.results (the final generated report)
print("\nBasic Information:")
print(scanner.results.get("basic_info"))

print("\nHeaders:")
print(scanner.results.get("headers"))

print("\nRedirect Information:")
print(scanner.results.get("redirects"))

print("\nSecurity Headers:")
print(scanner.results.get("security_headers"))

print("\nCookie Security:")
print(scanner.results.get("cookies"))

print("\nTLS Security:")
print(scanner.results.get("tls"))

print("\nHTTP Method Security:")
print(scanner.results.get("methods"))

print("\nCORS Security:")
print(scanner.results.get("cors"))

print("\nrobots.txt Analysis:")
print(scanner.results.get("robots"))

print("\nCommon Endpoint Discovery:")
print(scanner.results.get("endpoints"))

print("\nTechnology Detection:")
print(scanner.results.get("technology"))

print("\nInformation Disclosure:")
print(scanner.results.get("information_disclosure"))

print("\nSecurity Score:")
print(scanner.results.get("security_score"))