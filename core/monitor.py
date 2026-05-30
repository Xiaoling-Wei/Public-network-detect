"""
Background Network Monitor

Runs in a QThread and continuously watches for:
  1. Network change (SSID switch) → immediate re-scan
  2. Periodic interval elapsed    → scheduled re-scan
  3. App startup                  → first scan

Emits signals that the main window connects to the scan pipeline.
"""

import time
from PyQt6.QtCore import QThread, pyqtSignal
from utils.network_utils import get_current_ssid

POLL_SECONDS = 10   # How often to check for SSID changes


class NetworkMonitor(QThread):
    scan_requested  = pyqtSignal(str)        # reason: "startup" | "network_changed" | "interval"
    network_changed = pyqtSignal(str, str)   # (old_ssid, new_ssid)
    countdown_tick  = pyqtSignal(int, int)   # (minutes_remaining, seconds_remaining)

    def __init__(self, interval_minutes: int = 5, parent=None):
        super().__init__(parent)
        self._interval_sec   = interval_minutes * 60
        self._running        = True
        self._last_ssid      = ""
        self._last_scan_time = 0.0
        self._scanning       = False   # set True while a scan is running

    # ------------------------------------------------------------------
    # Control
    # ------------------------------------------------------------------

    def set_interval(self, minutes: int):
        self._interval_sec = minutes * 60

    def stop(self):
        self._running = False

    def notify_scan_started(self):
        self._scanning = True

    def notify_scan_finished(self):
        self._scanning = False
        self._last_scan_time = time.time()

    def trigger_now(self):
        """Force an immediate scan (e.g., manual button press)."""
        self._last_scan_time = 0.0

    # ------------------------------------------------------------------
    # Thread loop
    # ------------------------------------------------------------------

    def run(self):
        # Grab initial SSID then request startup scan
        self._last_ssid = get_current_ssid()
        self.scan_requested.emit("startup")
        self._last_scan_time = time.time()

        while self._running:
            # Sleep in small steps so stop() is responsive
            for _ in range(POLL_SECONDS):
                if not self._running:
                    return
                time.sleep(1)

            current_ssid = get_current_ssid()
            elapsed      = time.time() - self._last_scan_time

            if current_ssid != self._last_ssid:
                old, self._last_ssid = self._last_ssid, current_ssid
                self.network_changed.emit(old, current_ssid)
                if not self._scanning:
                    self.scan_requested.emit("network_changed")
                    self._last_scan_time = time.time()

            elif elapsed >= self._interval_sec and not self._scanning:
                self.scan_requested.emit("interval")
                self._last_scan_time = time.time()

            else:
                remaining = max(0, int(self._interval_sec - elapsed))
                self.countdown_tick.emit(remaining // 60, remaining % 60)
