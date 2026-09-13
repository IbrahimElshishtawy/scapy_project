#!/usr/bin/env python3
"""
HTTP & Web Reconnaissance Module (Requests Toolkit)
Provides tools for interacting with web protocols, REST APIs, and HTTP services using the 'requests' library.
Key functions:
- requests.get(url): Website health check & response timing
- response.status_code: HTTP response status analysis
- response.headers: Server banner grabbing & Security headers audit
- response.json(): REST API integration & IP Geolocation/Threat Intel
- requests.post(url, data/json): Sending data / API payloads
- requests.Session(): Persistent session & cookie tracking
"""

import json
import time
import requests

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS - Enforces HTTPS communication"),
    ("Content-Security-Policy", "CSP - Mitigates XSS and data injection attacks"),
    ("X-Frame-Options", "Prevents Clickjacking attacks in iframes"),
    ("X-Content-Type-Options", "Prevents MIME-sniffing vulnerabilities"),
    ("Referrer-Policy", "Controls referrer information passed in requests"),
    ("Permissions-Policy", "Controls browser features and APIs allowed")
]

DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0 (ScapyToolkit/1.0)"


def format_status_code(code: int) -> str:
    """Returns colored string representation of HTTP status code."""
    if 200 <= code < 300:
        return f"\033[92m{code} OK\033[0m"
    elif 300 <= code < 400:
        return f"\033[94m{code} Redirect\033[0m"
    elif 400 <= code < 500:
        return f"\033[93m{code} Client Error\033[0m"
    elif 500 <= code < 600:
        return f"\033[91m{code} Server Error\033[0m"
    return str(code)


def check_website(url: str, timeout: int = 10, follow_redirects: bool = True):
    """
    Uses requests.get(url) to test website availability,
    inspect status_code, measure latency, and extract headers.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n[*] Sending GET request to: {url} ...")
    headers = {"User-Agent": DEFAULT_USER_AGENT}

    try:
        start_time = time.time()
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=follow_redirects)
        latency = (time.time() - start_time) * 1000  # ms

        print("=" * 65)
        print("             HTTP GET INSPECTION RESULT")
        print("=" * 65)
        print(f"Target URL       : {response.url}")
        print(f"Status Code      : {format_status_code(response.status_code)}")
        print(f"Response Time    : {latency:.1f} ms")
        print(f"Content Length   : {len(response.content)} bytes")
        print(f"Encoding         : {response.encoding}")

        # Server Banner
        server = response.headers.get("Server", "Not disclosed")
        powered_by = response.headers.get("X-Powered-By", "Not disclosed")
        print(f"Server Banner    : \033[1m{server}\033[0m")
        if powered_by != "Not disclosed":
            print(f"Powered By       : \033[1m{powered_by}\033[0m")

        print("=" * 65 + "\n")
        return response

    except requests.exceptions.SSLError as e:
        print(f"\033[91m[-] SSL/TLS Certificate Error:\033[0m {e}")
    except requests.exceptions.ConnectionError as e:
        print(f"\033[91m[-] Connection Failed (Host may be down or unreachable):\033[0m {e}")
    except requests.exceptions.Timeout:
        print(f"\033[91m[-] Request timed out after {timeout} seconds.\033[0m")
    except Exception as e:
        print(f"[-] Request error: {e}")

    return None


def audit_security_headers(response):
    """
    Analyzes response.headers for crucial HTTP security headers.
    """
    if response is None:
        print("[-] No response to audit.")
        return

    print("\n" + "=" * 70)
    print("             HTTP RESPONSE HEADERS & SECURITY AUDIT")
    print("=" * 70)
    print(f"{'Header':<28} | {'Status':<12} | {'Description'}")
    print("-" * 70)

    headers = response.headers
    present_count = 0

    for header, desc in SECURITY_HEADERS:
        if header in headers:
            present_count += 1
            val = headers[header][:25] + "..." if len(headers[header]) > 25 else headers[header]
            print(f"{header:<28} | \033[92mPresent\033[0m     | {desc} (\033[90m{val}\033[0m)")
        else:
            print(f"{header:<28} | \033[91mMissing\033[0m     | {desc}")

    print("=" * 70)
    score = (present_count / len(SECURITY_HEADERS)) * 100
    print(f"Security Headers Score: {present_count}/{len(SECURITY_HEADERS)} ({score:.1f}%)\n")


def ip_threat_and_geo_lookup(ip_or_domain: str):
    """
    Demonstrates response.json() by querying a free IP Geolocation & ASN API.
    Extracts geographic location, ISP, ASN, and organization details.
    """
    print(f"\n[*] Querying IP Intelligence API for: '{ip_or_domain}' ...")
    url = f"http://ip-api.com/json/{ip_or_domain}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": DEFAULT_USER_AGENT})
        if resp.status_code == 200:
            # Parse JSON using response.json()
            data = resp.json()

            if data.get("status") == "fail":
                print(f"[-] API query failed: {data.get('message', 'Invalid target')}")
                return None

            print("=" * 60)
            print("         IP GEOLOCATION & NETWORK INTELLIGENCE")
            print("=" * 60)
            print(f"IP Address  : {data.get('query')}")
            print(f"Country     : {data.get('country')} ({data.get('countryCode')})")
            print(f"City/Region : {data.get('city')}, {data.get('regionName')}")
            print(f"Coordinates : {data.get('lat')}, {data.get('lon')}")
            print(f"Timezone    : {data.get('timezone')}")
            print(f"ISP         : \033[1m{data.get('isp')}\033[0m")
            print(f"Org / Entity: {data.get('org')}")
            print(f"ASN         : {data.get('as')}")
            print("=" * 60 + "\n")
            return data
        else:
            print(f"[-] API returned status code: {resp.status_code}")
    except Exception as e:
        print(f"[-] Geolocation query error: {e}")
    return None


def send_post_request(url: str, data: dict = None, json_data: dict = None):
    """
    Uses requests.post(url, data=... / json=...) to transmit form data or JSON payloads.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n[*] Sending POST request to: {url} ...")
    headers = {"User-Agent": DEFAULT_USER_AGENT}

    try:
        if json_data:
            resp = requests.post(url, json=json_data, headers=headers, timeout=10)
        else:
            resp = requests.post(url, data=data, headers=headers, timeout=10)

        print("=" * 60)
        print("              POST REQUEST RESULT")
        print("=" * 60)
        print(f"Target URL   : {resp.url}")
        print(f"Status Code  : {format_status_code(resp.status_code)}")
        print(f"Content-Type : {resp.headers.get('Content-Type', 'Unknown')}")
        print("Preview of response body:")
        print(resp.text[:300] + ("..." if len(resp.text) > 300 else ""))
        print("=" * 60 + "\n")
        return resp
    except Exception as e:
        print(f"[-] POST request error: {e}")
        return None


def demonstrate_session(url: str):
    """
    Demonstrates requests.Session() to maintain cookies and persistent headers
    across multiple consecutive HTTP requests.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n[*] Initializing requests.Session() for {url} ...")
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT, "X-Client": "ScapyNetworkToolkit"})

    # Step 1: First request to fetch cookies
    print("[1] Executing initial GET to establish session and collect cookies...")
    r1 = session.get(url, timeout=10)
    print(f"    -> Response Code: {format_status_code(r1.status_code)}")
    print(f"    -> Session Cookies Captured: {len(session.cookies)}")
    for cookie in session.cookies:
        print(f"       Cookie: {cookie.name} = {cookie.value[:20]}... (domain={cookie.domain})")

    # Step 2: Second request using the maintained session
    print("\n[2] Executing second GET under the same persistent session...")
    r2 = session.get(url, timeout=10)
    print(f"    -> Response Code: {format_status_code(r2.status_code)}")
    print(f"    -> Session successfully preserved across multiple requests!")
    session.close()


def run_interactive_http_menu():
    """Interactive CLI menu for the Requests & HTTP Recon module."""
    while True:
        print("\n" + "=" * 60)
        print("   🌐 HTTP & WEB RECONNAISSANCE TOOLKIT (Requests)")
        print("=" * 60)
        print("1) Check Website Health & Banner Grabbing  (requests.get)")
        print("2) Audit HTTP Response Security Headers   (response.headers)")
        print("3) IP / Domain Geolocation & Threat Intel (response.json)")
        print("4) Send Custom POST Request               (requests.post)")
        print("5) Demonstrate Persistent Session         (requests.Session)")
        print("6) Back to Main Menu")
        print("=" * 60)

        choice = input("Select an option [1-6]: ").strip()
        if choice == "1":
            target = input("Enter website URL or domain (e.g. google.com, httpbin.org): ").strip()
            if target:
                check_website(target)
        elif choice == "2":
            target = input("Enter website URL or domain to audit security headers: ").strip()
            if target:
                resp = check_website(target)
                if resp:
                    audit_security_headers(resp)
        elif choice == "3":
            target = input("Enter IP address or domain (e.g. 8.8.8.8 or github.com): ").strip()
            if target:
                ip_threat_and_geo_lookup(target)
        elif choice == "4":
            url = input("Enter POST target URL (e.g. https://httpbin.org/post): ").strip() or "https://httpbin.org/post"
            key = input("Enter sample form key (default: 'username'): ").strip() or "username"
            val = input("Enter sample form value (default: 'admin'): ").strip() or "admin"
            send_post_request(url, data={key: val})
        elif choice == "5":
            target = input("Enter URL to test session (default: https://httpbin.org/cookies/set/session_id/12345): ").strip()
            if not target:
                target = "https://httpbin.org/cookies/set/session_id/12345"
            demonstrate_session(target)
        elif choice == "6":
            break
        else:
            print("[-] Invalid option. Choose 1-6.")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        check_website(sys.argv[1])
    else:
        run_interactive_http_menu()
