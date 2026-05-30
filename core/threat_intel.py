"""
Threat Intelligence — AbuseIPDB integration

Checks gateway IP and DNS servers against AbuseIPDB.
Gracefully skipped when no API key is configured.
"""

import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = 6


def check_ip_reputation(ip: str, api_key: str) -> dict:
    result = {
        "ip": ip,
        "abuse_score": 0,
        "total_reports": 0,
        "country": "",
        "is_tor": False,
        "error": "",
    }
    if not api_key or not ip:
        result["error"] = "No API key — threat intel skipped."
        return result

    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Accept": "application/json", "Key": api_key},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            result["abuse_score"]   = data.get("abuseConfidenceScore", 0)
            result["total_reports"] = data.get("totalReports", 0)
            result["country"]       = data.get("countryCode", "")
            result["is_tor"]        = data.get("isTor", False)
        elif resp.status_code == 401:
            result["error"] = "Invalid AbuseIPDB API key."
        elif resp.status_code == 429:
            result["error"] = "AbuseIPDB rate limit reached."
        else:
            result["error"] = f"AbuseIPDB returned HTTP {resp.status_code}."
    except requests.Timeout:
        result["error"] = "AbuseIPDB request timed out."
    except Exception as e:
        result["error"] = str(e)

    return result


def detect_threat_intel(gateway_ip: str, dns_servers: list[str], api_key: str) -> dict:
    result = {
        "check": "Threat Intelligence",
        "status": "unknown",
        "detail": "",
        "ip_reports": [],
    }

    if not api_key:
        result["status"] = "unknown"
        result["detail"] = (
            "AbuseIPDB API key not configured — threat intelligence skipped.\n"
            "(Add your key in Settings to enable this check.)"
        )
        return result

    ips = list({ip for ip in [gateway_ip] + dns_servers if ip})
    reports = [check_ip_reputation(ip, api_key) for ip in ips]
    result["ip_reports"] = reports

    dangerous  = [r for r in reports if not r["error"] and r["abuse_score"] >= 50]
    suspicious = [r for r in reports if not r["error"] and 10 <= r["abuse_score"] < 50]

    if dangerous:
        result["status"] = "danger"
        result["detail"] = (
            f"High-risk IPs detected: {', '.join(r['ip'] for r in dangerous)}\n"
            f"These IPs are flagged in the AbuseIPDB threat database. Disconnect immediately."
        )
    elif suspicious:
        result["status"] = "warning"
        result["detail"] = (
            f"Suspicious IPs found: {', '.join(r['ip'] for r in suspicious)}\n"
            f"These IPs have some abuse reports. Proceed with caution."
        )
    else:
        all_errored = all(r["error"] for r in reports)
        if all_errored and reports:
            result["status"] = "unknown"
            result["detail"] = reports[0]["error"]
        else:
            result["status"] = "safe"
            result["detail"] = "All checked IPs have a clean reputation in AbuseIPDB."

    return result
