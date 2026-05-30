from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QStackedWidget, QStatusBar,
    QFrame, QSystemTrayIcon, QMenu
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap, QPainter, QColor, QBrush, QIcon, QAction

from db.database import Database
from core.monitor import NetworkMonitor


def _make_tray_icon(color: str) -> QIcon:
    px = QPixmap(18, 18)
    px.fill(QColor(0, 0, 0, 0))
    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QBrush(QColor(color)))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(1, 1, 16, 16)
    p.end()
    return QIcon(px)


TRAY_COLORS = {
    "Safe":        "#4caf50",
    "Low Risk":    "#8bc34a",
    "Medium Risk": "#ff9800",
    "High Risk":   "#f44336",
    "Critical":    "#b71c1c",
    "idle":        "#607d8b",
    "scanning":    "#4fc3f7",
}


class SidebarButton(QPushButton):
    def __init__(self, icon_char: str, text: str, parent=None):
        super().__init__(f"  {icon_char}  {text}", parent)
        self.setObjectName("nav-btn")
        self.setMinimumHeight(42)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_active(self, active: bool):
        self.setProperty("active", "true" if active else "false")
        self.style().unpolish(self)
        self.style().polish(self)


class MainWindow(QMainWindow):
    def __init__(self, db: Database):
        super().__init__()
        self.db = db
        self._active_index = 0

        self.setWindowTitle("Public Network Security Scanner")
        self.setMinimumSize(1000, 680)
        self.resize(1100, 720)

        self._build_ui()
        self._build_tray()
        self._start_monitor()
        self._navigate(0)

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        self.stack.setObjectName("content-area")
        root.addWidget(self.stack, stretch=1)

        self._add_pages()

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Initializing…")

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(190)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        logo_frame = QFrame()
        logo_layout = QVBoxLayout(logo_frame)
        logo_layout.setContentsMargins(16, 20, 16, 16)

        title = QLabel("🛡 NetScan")
        title.setObjectName("app-title")
        subtitle = QLabel("Public Wi-Fi Security")
        subtitle.setObjectName("app-subtitle")
        logo_layout.addWidget(title)
        logo_layout.addWidget(subtitle)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(logo_frame)
        layout.addWidget(sep)
        layout.addSpacing(8)

        nav_items = [("📊", "Dashboard"), ("🔍", "Scan"), ("📋", "History"), ("⚙️", "Settings")]
        self.nav_buttons = []
        for icon, label in nav_items:
            btn = SidebarButton(icon, label)
            btn.clicked.connect(lambda _, i=len(self.nav_buttons): self._navigate(i))
            self.nav_buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch()

        # Monitoring status badge in sidebar
        self.monitor_badge = QLabel("● Monitoring")
        self.monitor_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.monitor_badge.setStyleSheet("color: #4caf50; font-size: 11px; padding: 6px;")
        layout.addWidget(self.monitor_badge)

        ver = QLabel("v1.0.0")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver.setStyleSheet("color: #3a4560; font-size: 11px; padding: 4px;")
        layout.addWidget(ver)

        return sidebar

    def _add_pages(self):
        from ui.dashboard     import DashboardPage
        from ui.scan_panel    import ScanPage
        from ui.history_view  import HistoryPage
        from ui.settings_view import SettingsPage

        self.dashboard_page = DashboardPage(self.db, self)
        self.scan_page       = ScanPage(self.db, self)
        self.history_page    = HistoryPage(self.db, self)
        self.settings_page   = SettingsPage(self.db, self)

        self.stack.addWidget(self.dashboard_page)
        self.stack.addWidget(self.scan_page)
        self.stack.addWidget(self.history_page)
        self.stack.addWidget(self.settings_page)

        self.scan_page.scan_saved.connect(self.history_page.refresh)
        self.scan_page.scan_saved.connect(self.dashboard_page.refresh_last_scan)
        self.scan_page.scan_saved.connect(self._on_scan_result)
        self.scan_page.scan_started.connect(self._on_scan_started)
        self.scan_page.request_navigate.connect(self._navigate)

    # ------------------------------------------------------------------
    # System Tray
    # ------------------------------------------------------------------

    def _build_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(_make_tray_icon(TRAY_COLORS["idle"]))
        self.tray.setToolTip("NetScan — Monitoring")

        menu = QMenu()
        show_action = QAction("Show / Hide", self)
        show_action.triggered.connect(self._toggle_window)

        scan_action = QAction("Scan Now", self)
        scan_action.triggered.connect(self._manual_scan)

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self._quit_app)

        menu.addAction(show_action)
        menu.addAction(scan_action)
        menu.addSeparator()
        menu.addAction(quit_action)

        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._on_tray_activated)
        self.tray.show()

    def _toggle_window(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()
            self.raise_()
            self.activateWindow()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._toggle_window()

    def _quit_app(self):
        if hasattr(self, "_monitor"):
            self._monitor.stop()
        self.tray.hide()
        from PyQt6.QtWidgets import QApplication
        QApplication.quit()

    # ------------------------------------------------------------------
    # Monitor
    # ------------------------------------------------------------------

    def _start_monitor(self):
        interval = int(self.db.get_setting("scan_interval_minutes", "5"))
        self._monitor = NetworkMonitor(interval_minutes=interval)
        self._monitor.scan_requested.connect(self._on_scan_requested)
        self._monitor.network_changed.connect(self._on_network_changed)
        self._monitor.countdown_tick.connect(self._on_countdown)
        self._monitor.start()

    def _on_scan_requested(self, reason: str):
        labels = {
            "startup":         "Auto-scan: startup",
            "network_changed": "Auto-scan: network changed",
            "interval":        "Auto-scan: scheduled",
        }
        self.status_bar.showMessage(labels.get(reason, "Auto-scanning…"))
        self.monitor_badge.setText("⟳ Scanning…")
        self.monitor_badge.setStyleSheet("color: #4fc3f7; font-size: 11px; padding: 6px;")
        self.tray.setIcon(_make_tray_icon(TRAY_COLORS["scanning"]))
        self.tray.setToolTip("NetScan — Scanning…")
        self._monitor.notify_scan_started()
        self.scan_page.auto_scan(reason)

    def _on_network_changed(self, old_ssid: str, new_ssid: str):
        self.tray.showMessage(
            "Network Changed",
            f"Switched from '{old_ssid}' to '{new_ssid}'. Scanning new network…",
            QSystemTrayIcon.MessageIcon.Information, 4000
        )

    def _on_countdown(self, mins: int, secs: int):
        self.status_bar.showMessage(f"Monitoring active — next scan in {mins}:{secs:02d}")

    def _on_scan_started(self):
        self._monitor.notify_scan_started()

    def _on_scan_result(self, summary: dict):
        self._monitor.notify_scan_finished()
        risk  = summary.get("risk_level", "idle")
        score = summary.get("score", 0)
        color = TRAY_COLORS.get(risk, "#607d8b")

        self.tray.setIcon(_make_tray_icon(color))
        self.tray.setToolTip(f"NetScan — {risk}  ({score}/10)")
        self.monitor_badge.setText("● Monitoring")
        self.monitor_badge.setStyleSheet(f"color: {color}; font-size: 11px; padding: 6px;")

        # Tray notification for dangerous findings
        dangers = [
            v.get("check", k)
            for k, v in summary.get("results", {}).items()
            if v.get("status") == "danger"
        ]
        if dangers:
            self.tray.showMessage(
                "⚠ Security Risk Detected",
                f"Issues found: {', '.join(dangers)}\nClick to view details.",
                QSystemTrayIcon.MessageIcon.Critical, 6000
            )

        # Reload scan interval in case it was changed in Settings
        new_interval = int(self.db.get_setting("scan_interval_minutes", "5"))
        self._monitor.set_interval(new_interval)

    def _manual_scan(self):
        self._monitor.trigger_now()
        self.scan_page.auto_scan("manual")
        self._navigate(1)

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def _navigate(self, index: int):
        self._active_index = index
        self.stack.setCurrentIndex(index)
        labels = ["Dashboard", "Scan", "History", "Settings"]
        for i, btn in enumerate(self.nav_buttons):
            btn.set_active(i == index)

    def set_status(self, message: str):
        self.status_bar.showMessage(message)

    def closeEvent(self, event):
        # Minimize to tray instead of closing
        event.ignore()
        self.hide()
        self.tray.showMessage(
            "NetScan",
            "Still monitoring in the background. Right-click the tray icon to quit.",
            QSystemTrayIcon.MessageIcon.Information, 3000
        )
