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
    scan_saved      = pyqtSignal(dict)
    request_navigate = pyqtSignal(int)

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self._scan_worker: ScanWorker | None = None
        self._ai_worker:   AIWorker   | None = None
        self._last_summary: dict = {}
        self._build_ui()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 20)
        outer.setSpacing(16)

        # Title row
        title_row = QHBoxLayout()
        title = QLabel("Scan")
        title.setObjectName("page-title")
        title_row.addWidget(title)
        title_row.addStretch()

        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setObjectName("btn-primary")
        self.scan_btn.setFixedSize(120, 38)
        self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_btn.clicked.connect(self._start_scan)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("btn-secondary")
        self.cancel_btn.setFixedSize(80, 38)
        self.cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cancel_btn.clicked.connect(self._cancel_scan)
        self.cancel_btn.setVisible(False)

        title_row.addWidget(self.scan_btn)
        title_row.addWidget(self.cancel_btn)
        outer.addLayout(title_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(6)
        outer.addWidget(self.progress_bar)

        self.progress_label = QLabel('Click "Start Scan" to analyze the current network.')
        self.progress_label.setStyleSheet("color: #6b7a99; font-size: 12px;")
        outer.addWidget(self.progress_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        content = QWidget()
        self._results_layout = QVBoxLayout(content)
        self._results_layout.setContentsMargins(0, 0, 8, 0)
        self._results_layout.setSpacing(12)
        scroll.setWidget(content)

        # Score + network info
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

        self.ai_status_lbl = QLabel("Waiting for scan to complete…")
        self.ai_status_lbl.setObjectName("ai-text")
        self.ai_status_lbl.setWordWrap(True)
        ai_layout.addWidget(self.ai_status_lbl)

        self.ai_recs_layout = QVBoxLayout()
        ai_layout.addLayout(self.ai_recs_layout)

        self._results_layout.addWidget(self.ai_panel)

        # Bottom buttons
        btn_row = QHBoxLayout()
        self.save_btn = QPushButton("Save Report")
        self.save_btn.setObjectName("btn-primary")
        self.save_btn.setFixedHeight(38)
        self.save_btn.setVisible(False)
        self.save_btn.clicked.connect(self._save_report)

        self.view_history_btn = QPushButton("View History")
        self.view_history_btn.setObjectName("btn-secondary")
        self.view_history_btn.setFixedHeight(38)
        self.view_history_btn.setVisible(False)
        self.view_history_btn.clicked.connect(lambda: self.request_navigate.emit(2))

        btn_row.addWidget(self.save_btn)
        btn_row.addWidget(self.view_history_btn)
        btn_row.addStretch()
        self._results_layout.addLayout(btn_row)
        self._results_layout.addStretch()

    # ------------------------------------------------------------------

    def _start_scan(self):
        self._clear_results()
        self.scan_btn.setEnabled(False)
        self.cancel_btn.setVisible(True)
        self.save_btn.setVisible(False)
        self.view_history_btn.setVisible(False)
        self.progress_bar.setValue(0)
        self.ai_status_lbl.setText("Waiting for scan to complete…")

        api_key_abuse = self.db.get_setting("abuse_api_key")
        self._scan_worker = ScanWorker(api_key_abuse=api_key_abuse)
        self._scan_worker.progress.connect(self._on_progress)
        self._scan_worker.check_done.connect(self._on_check_done)
        self._scan_worker.scan_complete.connect(self._on_scan_complete)
        self._scan_worker.scan_error.connect(self._on_scan_error)
        self._scan_worker.start()

    def _cancel_scan(self):
        if self._scan_worker and self._scan_worker.isRunning():
            self._scan_worker.cancel()
        self._reset_scan_ui("Scan cancelled.")

    def _clear_results(self):
        for layout in [self._checks_layout, self.ai_recs_layout]:
            while layout.count():
                item = layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
        self.score_widget.set_score(0, "Scanning…")
        for card in [self.ssid_card, self.gw_card, self.dns_card, self.enc_card]:
            card.set_value("—")

    def _reset_scan_ui(self, msg: str = ""):
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setVisible(False)
        if msg:
            self.progress_label.setText(msg)

    def _on_progress(self, percent: int, step: str):
        self.progress_bar.setValue(percent)
        self.progress_label.setText(step)

    def _on_check_done(self, result: dict):
        self._checks_layout.addWidget(
            CheckResultItem(result.get("check", "Check"), result.get("status", "unknown"), result.get("detail", ""))
        )

    def _on_scan_complete(self, summary: dict):
        self._last_summary = summary
        self.score_widget.set_score(summary.get("score", 0), summary.get("risk_level", "Unknown"))

        info = summary.get("network_info", {})
        self.ssid_card.set_value(summary.get("ssid", "—"))
        self.gw_card.set_value(summary.get("gateway_ip", "—"))
        dns = info.get("dns_servers", [])
        self.dns_card.set_value(dns[0] if dns else "—")
        self.enc_card.set_value(info.get("wifi_security", "—"))

        self.cancel_btn.setVisible(False)
        self.scan_btn.setEnabled(True)
        self.save_btn.setVisible(True)
        self.view_history_btn.setVisible(True)

        self._save_report(silent=True)

        # Launch AI analysis
        self.ai_status_lbl.setText("Requesting AI analysis…")
        provider = self.db.get_setting("ai_provider", "openai")
        api_key  = self.db.get_setting("ai_api_key")
        model    = self.db.get_setting("ai_model")
        self._ai_worker = AIWorker(summary, provider, api_key, model)
        self._ai_worker.analysis_done.connect(self._on_ai_done)
        self._ai_worker.analysis_error.connect(self._on_ai_error)
        self._ai_worker.start()

    def _on_scan_error(self, error: str):
        self.progress_label.setText(f"Scan error: {error}")
        self._reset_scan_ui()

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

        self._last_summary["ai_analysis"] = self.ai_status_lbl.text()
        self._last_summary["ai_recommendations"] = analysis.get("recommendations", [])

    def _on_ai_error(self, error: str):
        self.ai_status_lbl.setText(f"AI analysis failed: {error}")

    def _save_report(self, silent: bool = False):
        if not self._last_summary:
            return
        record_id = self.db.save_scan(self._last_summary)
        self._last_summary["_db_id"] = record_id
        if not silent:
            self.progress_label.setText("Report saved to history.")
        self.scan_saved.emit(self._last_summary)
