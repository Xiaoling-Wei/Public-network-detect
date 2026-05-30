"""
DNS Hijacking Detector

Queries test domains through the local resolver and two trusted public
resolvers (8.8.8.8, 1.1.1.1). A mismatch strongly indicates DNS hijacking.
"""

from utils.network_utils import resolve_domain

TEST_DOMAINS = ["www.google.com", "www.cloudflare.com", "www.microsoft.com"]
TRUSTED_DNS  = ["8.8.8.8", "1.1.1.1"]


def detect_dns_hijacking(local_dns_servers: list[str]) -> dict:
    result = {
        "check": "DNS Hijacking Detection",
        "status": "unknown",
        "detail": "",
        "hijacked_domains": [],
        "suspicious_domains": [],
    }

    hijacked = []
    suspicious = []

    for domain in TEST_DOMAINS:
        trusted_ips: set[str] = set()
        for dns in TRUSTED_DNS:
            trusted_ips.update(resolve_domain(domain, dns_server=dns))

        local_ips = set(resolve_domain(domain))

        if not trusted_ips:
            continue  # No internet — skip

        if not local_ips:
            suspicious.append(domain)
            continue

        if not trusted_ips & local_ips:          # No IP in common
            hijacked.append({
                "domain": domain,
                "local": sorted(local_ips),
                "trusted": sorted(trusted_ips),
            })

    result["hijacked_domains"] = hijacked
    result["suspicious_domains"] = suspicious

    if hijacked:
        domains_str = ", ".join(d["domain"] for d in hijacked)
        result["status"] = "danger"
        result["detail"] = (
            f"DNS Hijacking detected! The following domains resolve differently from trusted DNS:\n"
            f"  {domains_str}\n"
            f"Your local DNS may be redirecting traffic to malicious servers."
        )
    elif suspicious:
        result["status"] = "warning"
        result["detail"] = (
            f"Some domains could not be resolved locally ({', '.join(suspicious)}).\n"
            f"DNS filtering or blocking may be in place."
        )
    else:
        result["status"] = "safe"
        result["detail"] = "DNS results match trusted resolvers. No hijacking detected."

    return result
