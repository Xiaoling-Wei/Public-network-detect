"""
Scanner Orchestrator — runs all detection modules via QThread.
"""

from PyQt6.QtCore import QThread, pyqtSignal

from utils.network_utils import (
    get_default_gateway, check_internet,
    get_current_ssid, get_current_bssid,
)
from utils.windows_utils import (
    get_dns_servers, get_wifi_security_type, get_wifi_signal_strength,
)
from core.arp_detector  import detect_arp_spoofing
from core.dns_checker   import detect_dns_hijacking
from core.ssl_checker   import detect_ssl_issues
from core.threat_intel  import detect_threat_intel


def _compute_score(checks: list[dict]) -> float:
    penalty = {"safe": 0, "unknown": 0.5, "warning": 2.5, "danger": 5}
    if not checks:
        return 5.0
    total = sum(penalty.get(c.get("status", "unknown"), 1) for c in checks)
    score = 10 * (1 - total / (len(checks) * 5))
    return round(max(0.0, min(10.0, score)), 1)


def _risk_label(score: float) -> str:
    if score >= 8: return "Safe"
    if score >= 6: return "Low Risk"
    if score >= 4: return "Medium Risk"
    if score >= 2: return "High Risk"
    return "Critical"


class ScanWorker(QThread):
    progress      = pyqtSignal(int, str)   # (percent, step label)
    check_done    = pyqtSignal(dict)       # single check result
    scan_complete = pyqtSignal(dict)       # full summary
    scan_error    = pyqtSignal(str)

    def __init__(self, api_key_abuse: str = "", parent=None):
        super().__init__(parent)
        self.api_key_abuse = api_key_abuse
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            self._run_scan()
        except Exception as e:
            self.scan_error.emit(str(e))

    def _run_scan(self):
        results = {}

        self.progress.emit(5, "Gathering network information…")
        gateway_ip, local_ip = get_default_gateway()
        ssid            = get_current_ssid()
        bssid           = get_current_bssid()
        dns_servers     = get_dns_servers()
        wifi_security   = get_wifi_security_type()
        signal_strength = get_wifi_signal_strength()
        has_internet    = check_internet()

        network_info = {
            "ssid": ssid, "bssid": bssid,
            "gateway_ip": gateway_ip, "local_ip": local_ip,
            "dns_servers": dns_servers, "wifi_security": wifi_security,
            "signal_strength": signal_strength, "has_internet": has_internet,
        }

        if self._cancelled: return

        self.progress.emit(20, "Checking for ARP spoofing…")
        arp = detect_arp_spoofing(gateway_ip, local_ip)
        results["arp"] = arp
        self.check_done.emit(arp)

        if self._cancelled: return

        self.progress.emit(40, "Checking for DNS hijacking…")
        dns = detect_dns_hijacking(dns_servers)
        results["dns"] = dns
        self.check_done.emit(dns)

        if self._cancelled: return

        self.progress.emit(60, "Verifying SSL/TLS certificates…")
        ssl_res = detect_ssl_issues()
        results["ssl"] = ssl_res
        self.check_done.emit(ssl_res)

        if self._cancelled: return

        self.progress.emit(80, "Querying threat intelligence…")
        threat = detect_threat_intel(gateway_ip, dns_servers, self.api_key_abuse)
        results["threat"] = threat
        self.check_done.emit(threat)

        if self._cancelled: return

        self.progress.emit(95, "Computing security score…")
        score = _compute_score(list(results.values()))

        summary = {
            "network_info": network_info,
            "ssid": ssid, "bssid": bssid,
            "gateway_ip": gateway_ip,
            "gateway_mac": results.get("arp", {}).get("cache_mac", ""),
            "score": score,
            "risk_level": _risk_label(score),
            "results": results,
        }

        self.progress.emit(100, "Scan complete")
        self.scan_complete.emit(summary)
