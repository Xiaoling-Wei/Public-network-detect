from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QScrollArea, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal

from db.database import Database
from ui.widgets import CheckResultItem, ScoreWidget, InfoCard
from core.scanner import ScanWorker
from ai.ai_worker import AIWorker


class ScanPage(QWidget):
    scan_saved       = pyqtSignal(dict)
    scan_started     = pyqtSignal()
    request_navigate = pyqtSignal(int)

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self._scan_worker: ScanWorker | None = None
        self._ai_worker:   AIWorker   | None = None
        self._last_summary: dict = {}
        self._is_scanning = False
        self._build_ui()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 20)
        outer.setSpacing(16)

        # Title row
        title_row = QHBoxLayout()
        title = QLabel("Live Scan")
        title.setObjectName("page-title")
        title_row.addWidget(title)
        title_row.addStretch()

        # Auto-monitoring badge
        self.auto_badge = QLabel("● Auto-monitoring")
        self.auto_badge.setStyleSheet(
            "color: #4caf50; background: #1a2e1a; border-radius: 10px;"
            " padding: 4px 12px; font-size: 12px; font-weight: bold;"
        )
        title_row.addWidget(self.auto_badge)

        # Manual trigger
        self.scan_now_btn = QPushButton("Scan Now")
        self.scan_now_btn.setObjectName("btn-secondary")
        self.scan_now_btn.setFixedSize(110, 36)
        self.scan_now_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_now_btn.clicked.connect(lambda: self.auto_scan("manual"))

        title_row.addWidget(self.scan_now_btn)
        outer.addLayout(title_row)

        # Progress bar + status
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(6)
        outer.addWidget(self.progress_bar)

        self.progress_label = QLabel("Waiting for first automatic scan…")
        self.progress_label.setStyleSheet("color: #6b7a99; font-size: 12px;")
        outer.addWidget(self.progress_label)

        # Results scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        content = QWidget()
        self._results_layout = QVBoxLayout(content)
        self._results_layout.setContentsMargins(0, 0, 8, 0)
        self._results_layout.setSpacing(12)
        scroll.setWidget(content)

        # Score + network info row
        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        score_frame = QFrame()
        score_frame.setObjectName("score-frame")
        sf_layout = QVBoxLayout(score_frame)
        sf_layout.setContentsMargins(12, 12, 12, 12)
        self.score_widget = ScoreWidget()
        sf_layout.addWidget(self.score_widget, alignment=Qt.AlignmentFlag.AlignCenter)
        top_row.addWidget(score_frame)

        net_col = QVBoxLayout()
        net_col.setSpacing(8)
        row1 = QHBoxLayout()
        row1.setSpacing(8)
        self.ssid_card = InfoCard("Wi-Fi Network", "—")
        self.gw_card   = InfoCard("Gateway", "—")
        row1.addWidget(self.ssid_card)
        row1.addWidget(self.gw_card)

        row2 = QHBoxLayout()
        row2.setSpacing(8)
        self.dns_card = InfoCard("DNS Server", "—")
        self.enc_card = InfoCard("Encryption", "—")
        row2.addWidget(self.dns_card)
        row2.addWidget(self.enc_card)

        net_col.addLayout(row1)
        net_col.addLayout(row2)

        # Last scan info
        self.last_scan_lbl = QLabel("")
        self.last_scan_lbl.setStyleSheet("color: #6b7a99; font-size: 11px;")
        net_col.addWidget(self.last_scan_lbl)
        net_col.addStretch()
        top_row.addLayout(net_col, stretch=1)
        self._results_layout.addLayout(top_row)

        # Check items
        checks_lbl = QLabel("Detection Results")
        checks_lbl.setObjectName("section-title")
        self._results_layout.addWidget(checks_lbl)

        self._checks_layout = QVBoxLayout()
        self._checks_layout.setSpacing(6)
        self._results_layout.addLayout(self._checks_layout)

        # AI analysis
        ai_lbl = QLabel("AI Security Analysis")
        ai_lbl.setObjectName("section-title")
        self._results_layout.addWidget(ai_lbl)

        self.ai_panel = QFrame()
        self.ai_panel.setObjectName("ai-panel")
        ai_layout = QVBoxLayout(self.ai_panel)
        ai_layout.setContentsMargins(14, 12, 14, 12)
        ai_layout.setSpacing(6)

        self.ai_status_lbl = QLabel("AI analysis will appear after the first scan completes.")
        self.ai_status_lbl.setObjectName("ai-text")
        self.ai_status_lbl.setWordWrap(True)
        ai_layout.addWidget(self.ai_status_lbl)

        self.ai_recs_layout = QVBoxLayout()
        ai_layout.addLayout(self.ai_recs_layout)

        self._results_layout.addWidget(self.ai_panel)
        self._results_layout.addStretch()

    # ------------------------------------------------------------------
    # Scan trigger (called by monitor or manual button)
    # ------------------------------------------------------------------

    def auto_scan(self, reason: str = "auto"):
        if self._is_scanning:
            return  # Ignore if already running

        self._is_scanning = True
        self.scan_started.emit()
        self._clear_results()
        self.scan_now_btn.setEnabled(False)

        reason_labels = {
            "startup":         "Auto-scan: starting up…",
            "network_changed": "Auto-scan: new network detected…",
            "interval":        "Auto-scan: scheduled check…",
            "manual":          "Manual scan triggered…",
        }
        self.progress_label.setText(reason_labels.get(reason, "Scanning…"))
        self.auto_badge.setText("⟳ Scanning…")
        self.auto_badge.setStyleSheet(
            "color: #4fc3f7; background: #1a2a3a; border-radius: 10px;"
            " padding: 4px 12px; font-size: 12px; font-weight: bold;"
        )

        api_key_abuse = self.db.get_setting("abuse_api_key")
        self._scan_worker = ScanWorker(api_key_abuse=api_key_abuse)
        self._scan_worker.progress.connect(self._on_progress)
        self._scan_worker.check_done.connect(self._on_check_done)
        self._scan_worker.scan_complete.connect(self._on_scan_complete)
        self._scan_worker.scan_error.connect(self._on_scan_error)
        self._scan_worker.start()

    def _clear_results(self):
        for layout in [self._checks_layout, self.ai_recs_layout]:
            while layout.count():
                item = layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
        self.score_widget.set_score(0, "Scanning…")
        for card in [self.ssid_card, self.gw_card, self.dns_card, self.enc_card]:
            card.set_value("—")

    # ------------------------------------------------------------------
    # Worker slots
    # ------------------------------------------------------------------

    def _on_progress(self, percent: int, step: str):
        self.progress_bar.setValue(percent)
        self.progress_label.setText(step)

    def _on_check_done(self, result: dict):
        self._checks_layout.addWidget(
            CheckResultItem(result.get("check", "Check"), result.get("status", "unknown"), result.get("detail", ""))
        )

    def _on_scan_complete(self, summary: dict):
        self._last_summary = summary
        self._is_scanning = False
        self.scan_now_btn.setEnabled(True)

        self.score_widget.set_score(summary.get("score", 0), summary.get("risk_level", "Unknown"))

        info = summary.get("network_info", {})
        self.ssid_card.set_value(summary.get("ssid", "—"))
        self.gw_card.set_value(summary.get("gateway_ip", "—"))
        dns = info.get("dns_servers", [])
        self.dns_card.set_value(dns[0] if dns else "—")
        self.enc_card.set_value(info.get("wifi_security", "—"))

        from datetime import datetime
        self.last_scan_lbl.setText(f"Last scan: {datetime.now().strftime('%H:%M:%S')}")

        # Restore badge
        risk   = summary.get("risk_level", "Unknown")
        colors = {"Safe": "#4caf50", "Low Risk": "#8bc34a", "Medium Risk": "#ff9800",
                  "High Risk": "#f44336", "Critical": "#b71c1c"}
        c = colors.get(risk, "#8a96b0")
        self.auto_badge.setText("● Auto-monitoring")
        self.auto_badge.setStyleSheet(
            f"color: {c}; background: #1a1d23; border-radius: 10px;"
            " padding: 4px 12px; font-size: 12px; font-weight: bold;"
        )

        # Save to DB
        self.db.save_scan(summary)
        self.scan_saved.emit(summary)

        # AI analysis
        self.ai_status_lbl.setText("Requesting AI analysis…")
        provider = self.db.get_setting("ai_provider", "openai")
        api_key  = self.db.get_setting("ai_api_key")
        model    = self.db.get_setting("ai_model")
        self._ai_worker = AIWorker(summary, provider, api_key, model)
        self._ai_worker.analysis_done.connect(self._on_ai_done)
        self._ai_worker.analysis_error.connect(self._on_ai_error)
        self._ai_worker.start()

    def _on_scan_error(self, error: str):
        self._is_scanning = False
        self.scan_now_btn.setEnabled(True)
        self.progress_label.setText(f"Scan error: {error}")
        self.auto_badge.setText("● Auto-monitoring")
        self.auto_badge.setStyleSheet(
            "color: #ff9800; background: #1a1d23; border-radius: 10px;"
            " padding: 4px 12px; font-size: 12px; font-weight: bold;"
        )

    def _on_ai_done(self, analysis: dict):
        if analysis.get("error"):
            self.ai_status_lbl.setText(f"AI note: {analysis['error']}")
        else:
            text = "\n\n".join(filter(None, [
                analysis.get("overall_assessment", ""),
                analysis.get("risk_summary", ""),
            ]))
            self.ai_status_lbl.setText(text)

        while self.ai_recs_layout.count():
            item = self.ai_recs_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for rec in analysis.get("recommendations", []):
            lbl = QLabel(f"• {rec}")
            lbl.setObjectName("ai-recommendation")
            lbl.setWordWrap(True)
            self.ai_recs_layout.addWidget(lbl)

    def _on_ai_error(self, error: str):
        self.ai_status_lbl.setText(f"AI analysis failed: {error}")
