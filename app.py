
from flask import Flask, render_template, request, jsonify
import requests
import socket
import ipaddress
from urllib.parse import urlparse

app = Flask(__name__)

# Security checks and their score weights.
CHECK_WEIGHTS = {
    "content_security_policy": 25,
    "strict_transport_security": 20,
    "x_content_type_options": 15,
    "x_frame_options": 15,
    "referrer_policy": 10,
    "permissions_policy": 5,
    "secure_cookies": 10
}


def validate_url(url):
    """Allow only HTTP/HTTPS URLs pointing to public IP addresses."""

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are allowed.")

    if not parsed.hostname:
        raise ValueError("Please enter a valid website URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not allowed.")

    # Restrict ports to standard web ports.
    if parsed.port not in (None, 80, 443):
        raise ValueError("Only standard web ports 80 and 443 are allowed.")

    hostname = parsed.hostname

    # Reject local hostnames.
    if hostname.lower() == "localhost" or hostname.lower().endswith(".localhost"):
        raise ValueError("Localhost addresses are not allowed.")

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ValueError("The website hostname could not be resolved.")

    if not addresses:
        raise ValueError("No IP address was found for this website.")

    # Reject the hostname if any resolved address is not globally routable.
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])

        if not ip.is_global:
            raise ValueError("Private or non-public IP addresses are not allowed.")

    return parsed


def get_cookie_headers(response):
    """Get individual Set-Cookie headers when available."""

    try:
        return response.raw.headers.getlist("Set-Cookie")
    except (AttributeError, TypeError):
        cookie = response.headers.get("Set-Cookie")
        return [cookie] if cookie else []


def analyze_headers(headers, cookie_headers, is_https):
    """Check security headers and calculate a score."""

    checks = []

    def add_check(key, name, passed, message, recommendation):
        checks.append({
            "key": key,
            "name": name,
            "passed": passed,
            "weight": CHECK_WEIGHTS[key],
            "message": message,
            "recommendation": recommendation
        })

    # 1. Content Security Policy
    csp = headers.get("Content-Security-Policy", "")

    add_check(
        "content_security_policy",
        "Content Security Policy",
        bool(csp.strip()),
        "Content Security Policy is present." if csp.strip()
        else "Content Security Policy is missing.",
        "Configure a Content-Security-Policy header that restricts trusted content sources."
    )

    # 2. HTTP Strict Transport Security
    hsts = headers.get("Strict-Transport-Security", "")

    if is_https:
        add_check(
            "strict_transport_security",
            "HTTP Strict Transport Security",
            bool(hsts.strip()),
            "HSTS is enabled." if hsts.strip()
            else "HSTS header is missing.",
            "Add Strict-Transport-Security with an appropriate max-age. Consider includeSubDomains only when all subdomains support HTTPS."
        )
    else:
        add_check(
            "strict_transport_security",
            "HTTP Strict Transport Security",
            False,
            "The website was reached over HTTP, not HTTPS.",
            "Enable HTTPS and redirect HTTP traffic to HTTPS before configuring HSTS."
        )

    # 3. Prevent MIME-type sniffing
    content_type_options = headers.get("X-Content-Type-Options", "")

    add_check(
        "x_content_type_options",
        "X-Content-Type-Options",
        content_type_options.lower().strip() == "nosniff",
        "MIME sniffing protection is enabled."
        if content_type_options.lower().strip() == "nosniff"
        else "X-Content-Type-Options: nosniff is missing.",
        "Set X-Content-Type-Options: nosniff."
    )

    # 4. Clickjacking protection
    x_frame = headers.get("X-Frame-Options", "")
    csp_lower = csp.lower()

    frame_protected = (
        x_frame.lower().strip() in ("deny", "sameorigin")
        or "frame-ancestors" in csp_lower
    )

    add_check(
        "x_frame_options",
        "Clickjacking Protection",
        frame_protected,
        "A recognized framing restriction was found."
        if frame_protected
        else "No X-Frame-Options or CSP frame-ancestors restriction was found.",
        "Configure X-Frame-Options: DENY or SAMEORIGIN, or a suitable CSP frame-ancestors directive."
    )

    # 5. Referrer Policy
    referrer = headers.get("Referrer-Policy", "")

    add_check(
        "referrer_policy",
        "Referrer-Policy",
        bool(referrer.strip()),
        "Referrer-Policy is present." if referrer.strip()
        else "Referrer-Policy is missing.",
        "Set a suitable Referrer-Policy, such as strict-origin-when-cross-origin."
    )

    # 6. Permissions Policy
    permissions = headers.get("Permissions-Policy", "")

    add_check(
        "permissions_policy",
        "Permissions-Policy",
        bool(permissions.strip()),
        "Permissions-Policy is present." if permissions.strip()
        else "Permissions-Policy is missing.",
        "Define a Permissions-Policy to restrict browser features your site does not need."
    )

    # 7. Cookie security flags
    if cookie_headers:
        cookies_secure = all(
            "secure" in cookie.lower() for cookie in cookie_headers
        )
        cookies_httponly = all(
            "httponly" in cookie.lower() for cookie in cookie_headers
        )
        cookies_samesite = all(
            "samesite=" in cookie.lower() for cookie in cookie_headers
        )

        cookies_pass = (
            is_https and cookies_secure and cookies_httponly and cookies_samesite
        )

        cookie_message = (
            "All observed cookies include Secure, HttpOnly and SameSite flags."
            if cookies_pass
            else "One or more observed cookies are missing recommended security flags."
        )
    else:
        cookies_pass = False
        cookie_message = (
            "No Set-Cookie headers were returned; cookie security could not be verified."
        )

    add_check(
        "secure_cookies",
        "Cookie Security",
        cookies_pass,
        cookie_message,
        "For sensitive cookies, use Secure, HttpOnly and an appropriate SameSite value. Review each cookie's purpose and requirements."
    )

    score = sum(
        check["weight"] for check in checks if check["passed"]
    )

    if score >= 80:
        risk = "Low"
    elif score >= 50:
        risk = "Medium"
    else:
        risk = "High"

    return {
        "score": score,
        "risk": risk,
        "checks": checks,
        "passed": sum(1 for check in checks if check["passed"]),
        "failed": sum(1 for check in checks if not check["passed"])
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Please enter a website URL."}), 400

    # Add HTTPS if the user did not enter a scheme.
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = validate_url(url)

        # Do not follow redirects automatically.
        # Limit the response body read; only headers are needed here.
        response = requests.get(
            url,
            timeout=(5, 10),
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "CyberShield-Header-Analyzer/1.0"}
        )

        try:
            headers = dict(response.headers)
            cookie_headers = get_cookie_headers(response)

            result = analyze_headers(
                headers,
                cookie_headers,
                parsed.scheme == "https"
            )

            result["url"] = url
            result["status_code"] = response.status_code
            result["redirect_location"] = response.headers.get("Location")
            result["note"] = (
                "This is a security-header check, not a complete vulnerability scan. "
                "A redirect was not followed."
            )

            return jsonify(result)

        finally:
            response.close()

    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    except requests.exceptions.Timeout:
        return jsonify({"error": "The website took too long to respond."}), 504

    except requests.exceptions.RequestException:
        return jsonify({
            "error": "Could not connect securely to this website. Check the URL and try again."
        }), 502

    except Exception:
        app.logger.exception("Unexpected analysis error")
        return jsonify({"error": "An unexpected server error occurred."}), 500


if __name__ == "__main__":
    app.run(debug=True)
