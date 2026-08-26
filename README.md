# Web Security Scanner

A modular Python-based web security scanner designed to perform HTTP reconnaissance and identify common web security configuration issues.

This project is being built from scratch as a learning project to understand how web security tools work internally.

## Project Goal

The goal of this project is to build a modular security scanner while learning about:

- HTTP and HTTPS
- Web security headers
- TLS/SSL security
- HTTP methods
- Cookies and session security
- Redirect security
- Technology detection
- Information disclosure
- Security risk assessment
- Security reporting

## Current Features

### HTTP Scanning

- GET request support
- HEAD request support
- Configurable request timeout
- Response status analysis
- Response size detection
- Server and content-type detection

### Security Headers

Checks for common security headers:

- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options

### Redirect Analysis

- Detects redirect chains
- Tracks redirect count
- Detects HTTPS to HTTP downgrade redirects
- Shows original and final URL schemes

### HTTP Method Security

- Detects methods exposed through the `Allow` header
- Tests potentially risky HTTP methods:
  - TRACE
  - PUT
  - DELETE
  - PATCH

### Cookie Security

Analyzes cookie security attributes including:

- Secure flag
- HttpOnly flag
- SameSite attribute

### TLS/HTTPS Analysis

- Detects TLS version
- Checks certificate validity
- Checks hostname validation
- Displays certificate validity dates

### Technology Detection

Performs basic technology detection using HTTP response headers.

### Information Disclosure

Detects unnecessary technology and version information exposed through HTTP headers.

### Security Scoring

Generates an overall security score from **0 to 100** and categorizes the target into a risk level based on identified security issues.

### Reporting

Supports multiple output formats:

- Terminal output
- JSON reports
- HTML reports

### Automated Tests

The project includes automated tests for selected modules and reporting functionality.

## Installation

Clone the repository:

```bash
git clone https://github.com/hamza-loop/web-security-scanner.git