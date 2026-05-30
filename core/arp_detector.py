"""
ARP Spoofing Detector

Compares gateway MAC obtained via live ARP request against the system ARP
cache. A mismatch indicates potential ARP spoofing (MITM attack).

Falls back to a cache-only heuristic when Npcap is unavailable.
"""

from utils.network_utils import get_arp_cache


def _send_arp_request(target_ip: str, source_ip: str, timeout: float = 2.0) -> str:
    """Send a raw ARP Who-Has packet and return the replied MAC. Returns '' on failure."""
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip, psrc=source_ip)
        ans, _ = srp(pkt, timeout=timeout, verbose=False)
        if ans:
            return ans[0][1].hwsrc.lower()
    except Exception:
        pass
    return ""


def detect_arp_spoofing(gateway_ip: str, local_ip: str) -> dict:
    """
    Returns:
        status  : "safe" | "warning" | "danger" | "unknown"
        detail  : English explanation
        cache_mac, live_mac : MAC addresses found
    """
    result = {
        "check": "ARP Spoofing Detection",
        "status": "unknown",
        "detail": "",
        "cache_mac": "",
        "live_mac": "",
    }

    if not gateway_ip:
        result["detail"] = "No default gateway detected — ARP check skipped."
        return result

    cache_mac = get_arp_cache().get(gateway_ip, "")
    result["cache_mac"] = cache_mac

    live_mac = _send_arp_request(gateway_ip, local_ip)
    result["live_mac"] = live_mac

    if live_mac and cache_mac:
        if live_mac == cache_mac:
            result["status"] = "safe"
            result["detail"] = f"Gateway MAC is consistent ({cache_mac}). No ARP spoofing detected."
        else:
            result["status"] = "danger"
            result["detail"] = (
                f"ARP Spoofing detected! Gateway MAC mismatch:\n"
                f"  ARP Cache : {cache_mac}\n"
                f"  Live Probe: {live_mac}\n"
                f"A man-in-the-middle attack may be in progress. Disconnect immediately."
            )
    elif cache_mac:
        arp_cache = get_arp_cache()
        shared = sum(1 for mac in arp_cache.values() if mac == cache_mac)
        if shared > 3:
            result["status"] = "warning"
            result["detail"] = (
                f"Multiple IPs share the gateway MAC ({cache_mac}), which may indicate ARP spoofing.\n"
                f"Run as Administrator for a deeper live probe."
            )
        else:
            result["status"] = "safe"
            result["detail"] = (
                f"Gateway MAC: {cache_mac} (from system cache).\n"
                f"Run as Administrator to enable live ARP probing."
            )
    else:
        result["detail"] = "Could not retrieve gateway MAC address. ARP check skipped."

    return result
