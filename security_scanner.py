from scan_engine import run_security_scan


class SecurityScanner:
    """
    Main interface for running a web security scan.
    """

    def __init__(self, url, method="GET", timeout=10):
        self.url = url
        self.method = method
        self.timeout = timeout

        self.results = None

    def scan(self):
        """
        Run the complete security scan.
        """

        self.results = run_security_scan(
            self.url,
            method=self.method,
            timeout=self.timeout
        )

        return self.results


# --- Example Usage ---

if __name__ == "__main__":

    scanner = SecurityScanner("https://example.com")

    results = scanner.scan()

    if "error" in results:
        print("\nScan failed:")
        print(results)

    else:
        print("\nTarget Information:")
        print(results.get("target_info"))

        print("\nSecurity Headers:")
        print(results.get("security_headers"))

        print("\nCookie Security:")
        print(results.get("cookies"))

        print("\nTLS Security:")
        print(results.get("tls"))

        print("\nRedirect Analysis:")
        print(results.get("redirects"))

        print("\nHTTP Method Security:")
        print(results.get("methods"))

        print("\nCORS Security:")
        print(results.get("cors"))

        print("\nrobots.txt Analysis:")
        print(results.get("robots"))

        print("\nCommon Endpoint Discovery:")
        print(results.get("endpoints"))

        print("\nTechnology Detection:")
        print(results.get("technology"))

        print("\nInformation Disclosure:")
        print(results.get("information_disclosure"))

        print("\nSecurity Score:")
        print(results.get("security_score"))