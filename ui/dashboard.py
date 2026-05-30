from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QScrollArea, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal

from db.database import Database
from ui.widgets import ScoreWidget, CheckResultItem, InfoCard, RISK_COLORS


class DashboardPage(QWidget):
    navigate_to_scan = pyqtSignal()

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()
        self.refresh_last_scan()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 20)
        outer.setSpacing(16)

        # Title row with monitoring status
        title_row = QHBoxLayout()
        title = QLabel("Dashboard")
        title.setObjectName("page-title")
        title_row.addWidget(title)
        title_row.addStretch()

        self.status_badge = QLabel("● Auto-monitoring active")
        self.status_badge.setStyleSheet(
            "color: #4caf50; background: #1a2e1a; border-radius: 10px;"
            " padding: 4px 14px; font-size: 12px; font-weight: bold;"
        )
        title_row.addWidget(self.status_badge)
        outer.addLayout(title_row)

        # Countdown label
        self.countdown_lbl = QLabel("")
        self.countdown_lbl.setStyleSheet("color: #6b7a99; font-size: 11px;")
        outer.addWidget(self.countdown_lbl)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        content = QWidget()
        self._content_layout = QVBoxLayout(content)
        self._content_layout.setContentsMargins(0, 0, 8, 0)
        self._content_layout.setSpacing(16)
        scroll.setWidget(content)

        self._build_content()

    def _build_content(self):
        layout = self._content_layout

        # Score + info row
        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        score_frame = QFrame()
        score_frame.setObjectName("score-frame")
        sf_layout = QVBoxLayout(score_frame)
        sf_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sf_layout.setContentsMargins(16, 16, 16, 16)
        self.score_widget = ScoreWidget()
        sf_layout.addWidget(self.score_widget, alignment=Qt.AlignmentFlag.AlignCenter)
        top_row.addWidget(score_frame)

        info_col = QVBoxLayout()
        info_col.setSpacing(10)

        row1 = QHBoxLayout()
        row1.setSpacing(10)
        self.ssid_card    = InfoCard("Wi-Fi Network")
        self.gateway_card = InfoCard("Gateway")
        row1.addWidget(self.ssid_card)
        row1.addWidget(self.gateway_card)

        row2 = QHBoxLayout()
        row2.setSpacing(10)
        self.dns_card      = InfoCard("DNS Server")
        self.security_card = InfoCard("Encryption")
        row2.addWidget(self.dns_card)
        row2.addWidget(self.security_card)

        info_col.addLayout(row1)
        info_col.addLayout(row2)

        self.last_scan_label = QLabel("Waiting for first scan…")
        self.last_scan_label.setStyleSheet("color: #6b7a99; font-size: 12px;")
        info_col.addWidget(self.last_scan_label)

        scan_now_btn = QPushButton("Scan Now")
        scan_now_btn.setObjectName("btn-secondary")
        scan_now_btn.setFixedHeight(36)
        scan_now_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        scan_now_btn.clicked.connect(self.navigate_to_scan)
        info_col.addWidget(scan_now_btn)
        info_col.addStretch()

        top_row.addLayout(info_col, stretch=1)
        layout.addLayout(top_row)

        # Check results
        checks_title = QLabel("Latest Detection Results")
        checks_title.setObjectName("section-title")
        layout.addWidget(checks_title)

        self.checks_container = QVBoxLayout()
        self.checks_container.setSpacing(6)
        layout.addLayout(self.checks_container)

        # AI analysis
        ai_title = QLabel("AI Security Analysis")
        ai_title.setObjectName("section-title")
        layout.addWidget(ai_title)

        self.ai_panel = QFrame()
        self.ai_panel.setObjectName("ai-panel")
        ai_layout = QVBoxLayout(self.ai_panel)
        ai_layout.setContentsMargins(14, 12, 14, 12)
        ai_layout.setSpacing(8)

        self.ai_assessment = QLabel("AI analysis will appear automatically after the first scan.")
        self.ai_assessment.setObjectName("ai-text")
        self.ai_assessment.setWordWrap(True)
        ai_layout.addWidget(self.ai_assessment)

        self.ai_recs_layout = QVBoxLayout()
        ai_layout.addLayout(self.ai_recs_layout)

        layout.addWidget(self.ai_panel)
        layout.addStretch()

    # ------------------------------------------------------------------
    # Public update slots
    # ------------------------------------------------------------------

    def update_countdown(self, mins: int, secs: int):
        self.countdown_lbl.setText(f"Next scan in {mins}:{secs:02d}")

    def set_scanning(self):
        self.status_badge.setText("⟳ Scanning…")
        self.status_badge.setStyleSheet(
            "color: #4fc3f7; background: #1a2a3a; border-radius: 10px;"
            " padding: 4px 14px; font-size: 12px; font-weight: bold;"
        )
        self.countdown_lbl.setText("")

    def refresh_last_scan(self, scan_data: dict = None):
        if scan_data is None:
            history = self.db.get_history(limit=1)
            scan_data = history[0] if history else None

        if not scan_data:
            self.score_widget.set_score(0, "Not Scanned")
            return

        score = scan_data.get("score", 0)
        risk  = scan_data.get("risk_level", "Unknown")

        self.score_widget.set_score(score, risk)

        # Restore badge color
        color = RISK_COLORS.get(risk, "#8a96b0")
        self.status_badge.setText("● Auto-monitoring active")
        self.status_badge.setStyleSheet(
            f"color: {color}; background: #1a1d23; border-radius: 10px;"
            " padding: 4px 14px; font-size: 12px; font-weight: bold;"
        )

        net = scan_data.get("network_info", {})
        self.ssid_card.set_value(scan_data.get("ssid", "—"))
        self.gateway_card.set_value(scan_data.get("gateway_ip", "—"))
        dns_list = net.get("dns_servers", [])
        self.dns_card.set_value(dns_list[0] if dns_list else "—")
        self.security_card.set_value(net.get("wifi_security", "—"))
        self.last_scan_label.setText(f"Last scan: {scan_data.get('scan_time', '—')}")

        # Check items
        while self.checks_container.count():
            item = self.checks_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for key in ["arp", "dns", "ssl", "threat"]:
            r = scan_data.get("results", {}).get(key)
            if r:
                self.checks_container.addWidget(
                    CheckResultItem(r.get("check", key), r.get("status", "unknown"), r.get("detail", ""))
                )

        if scan_data.get("ai_analysis"):
            self.ai_assessment.setText(scan_data["ai_analysis"])

        while self.ai_recs_layout.count():
            item = self.ai_recs_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for rec in (scan_data.get("ai_recommendations") or []):
            lbl = QLabel(f"• {rec}")
            lbl.setObjectName("ai-recommendation")
            lbl.setWordWrap(True)
            self.ai_recs_layout.addWidget(lbl)
