"""Web UI for the Web Security Scanner.

Run:  python app.py   then open http://127.0.0.1:5000

The page posts a URL to /api/scan, which runs the same pipeline the CLI uses
(scan_engine.run_security_scan) and returns the report as JSON.
"""

import ipaddress
import json
import logging
import os
import re
import socket
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, render_template, request

from scan_engine import run_security_scan
from url_utils import normalize_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096  # the request only carries a URL

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}
IMPACT_RE = re.compile(r"\s*\((-\d+)\)\s*$")


def private_targets_allowed():
    """Scanning localhost / private networks is off unless explicitly enabled."""
    return os.environ.get("ALLOW_PRIVATE_TARGETS") == "1"


def is_private_target(hostname):
    """True if the hostname resolves to a private, loopback or reserved address."""
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # Let the scanner report the DNS failure itself.
        return False

    for info in addresses:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True

    return False


def normalize_findings(findings):
    """Make every finding a dict.

    scoring.calculate_score returns SecurityFinding dicts for most checks but
    plain strings such as "Cookie 'sid' missing Secure flag (-10)" for cookie
    and redirect checks. The UI needs one shape, so strings are converted and
    their severity is derived from the point deduction.
    """
    normalized = []

    for item in findings:
        if isinstance(item, dict):
            normalized.append(item)
            continue

        text = str(item)
        match = IMPACT_RE.search(text)
        impact = int(match.group(1)) if match else 0
        size = abs(impact)

        if size >= 15:
            severity = "High"
        elif size >= 8:
            severity = "Medium"
        else:
            severity = "Low"

        normalized.append({
            "name": IMPACT_RE.sub("", text),
            "severity": severity,
            "description": "",
            "score_impact": impact,
        })

    normalized.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.get("severity"), 3),
            f.get("score_impact", 0),
        )
    )
    return normalized


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def api_scan():
    payload = request.get_json(silent=True) or {}
    raw_url = payload.get("url", "")

    try:
        url = normalize_url(raw_url if isinstance(raw_url, str) else "")
    except ValueError as error:
        return jsonify(error=str(error)), 400

    hostname = urlparse(url).hostname

    if hostname and not private_targets_allowed() and is_private_target(hostname):
        return jsonify(
            error=(
                "This address points to a private or local network, "
                "so it can't be scanned from here."
            )
        ), 403

    logger.info("Web UI scan requested for %s", url)
    report = run_security_scan(url, timeout=10)

    if "error" in report:
        return jsonify(
            error=report["error"],
            error_type=report.get("error_type", "request"),
        ), 502

    score = report.get("security_score", {})
    score["findings"] = normalize_findings(score.get("findings", []))

    # default=str keeps odd values (tuples, datetimes) from breaking the response
    return Response(json.dumps(report, default=str), mimetype="application/json")


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )