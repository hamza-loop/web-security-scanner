from disclosure import analyze_information_disclosure


mock_headers = {
    "Server": "Apache/2.4.57",
    "X-Powered-By": "PHP/8.2.1"
}


result = analyze_information_disclosure(mock_headers)

print(result)