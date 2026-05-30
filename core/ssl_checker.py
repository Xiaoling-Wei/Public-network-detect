"""
SSL/TLS Certificate Checker

Tests HTTPS connections and inspects certificate validity, TLS version,
and expiry. Anomalies may indicate HTTPS interception (MITM).
"""

import ssl
import socket
from datetime import datetime, timezone

TEST_HOSTS = [
    ("www.google.com", 443),
    ("www.cloudflare.com", 443),
    ("www.microsoft.com", 443),
]


def _check_host(host: str, port: int, timeout: int = 5) -> dict:
    info = {
        "host": host,
        "valid": False,
        "tls_version": "",
        "cipher": "",
        "expires": "",
        "days_left": 0,
        "error": "",
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                info["tls_version"] = s.version() or ""
                info["cipher"] = s.cipher()[0] if s.cipher() else ""
                not_after = cert.get("notAfter", "")
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    info["expires"] = exp.strftime("%Y-%m-%d")
                    info["days_left"] = (exp - datetime.now(timezone.utc)).days
                info["valid"] = True
    except ssl.SSLCertVerificationError as e:
        info["error"] = f"Certificate verification failed: {e.reason}"
    except ssl.SSLError as e:
        info["error"] = f"SSL error: {str(e)}"
    except Exception as e:
        info["error"] = str(e)
    return info


def detect_ssl_issues() -> dict:
    result = {
        "check": "SSL/TLS Certificate Check",
        "status": "unknown",
        "detail": "",
        "hosts": [],
    }

    host_results = []
    errors = []
    warnings = []

    for host, port in TEST_HOSTS:
        info = _check_host(host, port)
        host_results.append(info)

        if info["error"]:
            errors.append(f"{host}: {info['error']}")
        elif not info["valid"]:
            errors.append(f"{host}: Invalid certificate")
        else:
            if info["tls_version"] and info["tls_version"] < "TLSv1.2":
                warnings.append(f"{host}: Outdated TLS ({info['tls_version']}) — downgrade attack risk")
            if info["days_left"] < 14:
                warnings.append(f"{host}: Certificate expires in {info['days_left']} days")

    result["hosts"] = host_results

    if errors:
        result["status"] = "danger"
        result["detail"] = (
            "SSL/TLS issues detected — possible HTTPS interception or MITM attack:\n"
            + "\n".join(f"  · {e}" for e in errors)
        )
    elif warnings:
        result["status"] = "warning"
        result["detail"] = (
            "SSL/TLS warnings found:\n"
            + "\n".join(f"  · {w}" for w in warnings)
        )
    else:
        reachable = [h for h in host_results if h["valid"]]
        if reachable:
            sample = reachable[0]
            earliest = min(h["expires"] for h in reachable if h["expires"])
            result["status"] = "safe"
            result["detail"] = (
                f"HTTPS connections are valid and secure.\n"
                f"  TLS: {sample['tls_version']}  |  Earliest expiry: {earliest}"
            )
        else:
            result["status"] = "unknown"
            result["detail"] = "Could not reach test servers. No internet access?"

    return result
