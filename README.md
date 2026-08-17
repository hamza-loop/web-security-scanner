# Web Security Scanner

A Python-based web security scanner designed to perform HTTP reconnaissance and identify common web security configuration issues.

## Project Goal

The goal of this project is to build a modular security scanner from scratch while learning how web security tools work internally.

The scanner will gradually include reconnaissance, security checks, risk assessment, and reporting capabilities.

## Current Features

- HTTP reconnaissance
- URL normalization
- HTTP status code detection
- Response header analysis
- Security header analysis
- Cookie analysis
- Redirect handling
- Command-line interface
- JSON output
- Report generation
- Modular project architecture

## Planned Features

- GET and HEAD request support
- Advanced redirect analysis
- TLS/HTTPS analysis
- CORS analysis
- Technology detection
- robots.txt analysis
- Common endpoint discovery
- Security misconfiguration checks
- Risk and severity scoring
- HTML reports
- Automated tests
- CI/CD
- AI-assisted security analysis

## Project Structure

```text
web-security-scanner/
├── main.py
├── scanner.py
├── headers.py
├── reporter.py
├── utils.py
├── tests/
├── reports/
├── requirements.txt
├── README.md
├── .gitignore
└── LICENSE