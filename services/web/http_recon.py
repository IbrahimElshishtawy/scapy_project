"""
HTTP Reconnaissance & Threat Intelligence Service (Requests).
"""

import time
from typing import Dict, Any, Optional
import requests


def check_website(url: str, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Sends GET request to inspect HTTP status, latency, server banner, and headers."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ScapySecurityToolkit/2.0"
    }
    if custom_headers:
        headers.update(custom_headers)

    start_time = time.time()
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        latency = round((time.time() - start_time) * 1000, 2)
        return {
            "success": True,
            "url": response.url,
            "status_code": response.status_code,
            "latency_ms": latency,
            "server": response.headers.get("Server", "Hidden / Not Disclosed"),
            "content_type": response.headers.get("Content-Type", "Unknown"),
            "headers": dict(response.headers),
            "error": None,
        }
    except Exception as e:
        return {
            "success": False,
            "url": url,
            "status_code": None,
            "latency_ms": None,
            "server": None,
            "content_type": None,
            "headers": {},
            "error": str(e),
        }


def audit_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Audits HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    standard_checks = {
        "strict-transport-security": "Strict-Transport-Security (HSTS)",
        "content-security-policy": "Content-Security-Policy (CSP)",
        "x-frame-options": "X-Frame-Options (Clickjacking Protection)",
        "x-content-type-options": "X-Content-Type-Options (MIME Sniffing)",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }

    present = {}
    missing = []
    for header_key, label in standard_checks.items():
        if header_key in headers_lower:
            present[label] = headers_lower[header_key]
        else:
            missing.append(label)

    score = int((len(present) / len(standard_checks)) * 100)
    grade = "A+" if score == 100 else ("A" if score >= 80 else ("B" if score >= 60 else ("C" if score >= 40 else "F")))

    return {
        "score_percent": score,
        "grade": grade,
        "present_headers": present,
        "missing_headers": missing,
    }


def ip_threat_and_geo_lookup(ip_or_domain: str) -> Dict[str, Any]:
    """Queries public IP API to fetch Geolocation, ISP, ASN, and Proxy/VPN indicators."""
    query = ip_or_domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    api_url = f"http://ip-api.com/json/{query}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting"
    try:
        resp = requests.get(api_url, timeout=8)
        data = resp.json()
        if data.get("status") == "success":
            return {"success": True, "data": data}
        return {"success": False, "error": data.get("message", "Lookup failed")}
    except Exception as e:
        return {"success": False, "error": str(e)}


def send_post_request(
    url: str,
    data_dict: Optional[Dict[str, Any]] = None,
    json_dict: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Executes HTTP POST request with form-data or JSON body."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    start = time.time()
    try:
        resp = requests.post(url, data=data_dict, json=json_dict, headers=headers, timeout=10)
        latency = round((time.time() - start) * 1000, 2)
        try:
            body_json = resp.json()
        except Exception:
            body_json = None
        return {
            "success": True,
            "status_code": resp.status_code,
            "latency_ms": latency,
            "headers": dict(resp.headers),
            "body_preview": resp.text[:1000],
            "body_json": body_json,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
