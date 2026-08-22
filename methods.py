import requests


def analyze_methods(url, timeout=10):
    results = {}

    try:
        options_response = requests.options(
            url,
            timeout=timeout
        )

        allow_header = options_response.headers.get("Allow")

        allowed_methods = []

        if allow_header:
            allowed_methods = [
                method.strip().upper()
                for method in allow_header.split(",")
            ]

        results["allow_header"] = allow_header
        results["allowed_methods"] = allowed_methods

        methods_to_test = [
            "TRACE",
            "PUT",
            "DELETE",
            "PATCH"
        ]

        method_results = {}

        for method in methods_to_test:
            response = requests.request(
                method,
                url,
                timeout=timeout
            )

            method_results[method] = {
                "status_code": response.status_code,
                "allowed": response.status_code < 400
            }

        results["method_tests"] = method_results

        return {
            "status": "success",
            **results
        }

    except requests.RequestException as error:
        return {
            "status": "failed",
            "error": str(error)
        }
