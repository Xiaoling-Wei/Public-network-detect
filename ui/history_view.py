from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QScrollArea, QFrame, QAbstractItemView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor

from db.database import Database
from ui.widgets import CheckResultItem, RISK_COLORS


class HistoryPage(QWidget):
    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self._history_data: list[dict] = []
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        title_row = QHBoxLayout()
        title = QLabel("History")
        title.setObjectName("page-title")
        title_row.addWidget(title)
        title_row.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setObjectName("btn-secondary")
        refresh_btn.setFixedHeight(36)
        refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh_btn.clicked.connect(self.refresh)

        clear_btn = QPushButton("Clear All")
        clear_btn.setObjectName("btn-danger")
        clear_btn.setFixedHeight(36)
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.clicked.connect(self._clear_history)

        title_row.addWidget(refresh_btn)
        title_row.addWidget(clear_btn)
        layout.addLayout(title_row)

        split = QHBoxLayout()
        split.setSpacing(16)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Time", "Network", "Score", "Risk", "Gateway"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setMinimumWidth(420)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        split.addWidget(self.table)

        # Detail panel
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        detail_scroll.setMinimumWidth(320)

        self.detail_widget = QWidget()
        self.detail_layout = QVBoxLayout(self.detail_widget)
        self.detail_layout.setContentsMargins(0, 0, 8, 0)
        self.detail_layout.setSpacing(10)
        detail_scroll.setWidget(self.detail_widget)

        self.detail_placeholder = QLabel("Select a record to view details.")
        self.detail_placeholder.setStyleSheet("color: #6b7a99; font-size: 13px;")
        self.detail_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail_layout.addWidget(self.detail_placeholder)
        self.detail_layout.addStretch()

        split.addWidget(detail_scroll)
        layout.addLayout(split)

    def refresh(self, _=None):
        self._history_data = self.db.get_history(50)
        self.table.setRowCount(0)
        for record in self._history_data:
            row = self.table.rowCount()
            self.table.insertRow(row)
            cells = [
                record.get("scan_time", ""),
                record.get("ssid", "Unknown"),
                f"{record.get('score', 0):.1f}",
                record.get("risk_level", "Unknown"),
                record.get("gateway_ip", ""),
            ]
            for col, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if col == 2:
                    cell.setForeground(QColor(self._score_color(record.get("score", 0))))
                if col == 3:
                    cell.setForeground(QColor(RISK_COLORS.get(record.get("risk_level", ""), "#8a96b0")))
                self.table.setItem(row, col, cell)

        if self.table.rowCount() > 0:
            self.table.selectRow(0)

    def _score_color(self, score: float) -> str:
        if score >= 8: return "#4caf50"
        if score >= 6: return "#8bc34a"
        if score >= 4: return "#ff9800"
        return "#f44336"

    def _on_selection_changed(self):
        row = self.table.currentRow()
        if 0 <= row < len(self._history_data):
            self._show_detail(self._history_data[row])

    def _show_detail(self, record: dict):
        while self.detail_layout.count():
            item = self.detail_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        risk = record.get("risk_level", "")
        score_lbl = QLabel(f"Score: {record.get('score', 0):.1f} / 10  —  {risk}")
        score_lbl.setStyleSheet(f"color: {RISK_COLORS.get(risk, '#8a96b0')}; font-size: 15px; font-weight: bold;")
        self.detail_layout.addWidget(score_lbl)

        info_lbl = QLabel(
            f"Network: {record.get('ssid', '—')}\n"
            f"Gateway: {record.get('gateway_ip', '—')}\n"
            f"Time:    {record.get('scan_time', '—')}"
        )
        info_lbl.setStyleSheet("color: #8a96b0; font-size: 12px;")
        self.detail_layout.addWidget(info_lbl)

        sep = QLabel("Detection Details")
        sep.setObjectName("section-title")
        self.detail_layout.addWidget(sep)

        for key in ["arp", "dns", "ssl", "threat"]:
            r = record.get("results", {}).get(key)
            if r:
                self.detail_layout.addWidget(
                    CheckResultItem(r.get("check", key), r.get("status", "unknown"), r.get("detail", ""))
                )

        ai_text = record.get("ai_analysis", "")
        if ai_text:
            ai_lbl = QLabel("AI Analysis")
            ai_lbl.setObjectName("section-title")
            self.detail_layout.addWidget(ai_lbl)
            ai_content = QLabel(ai_text)
            ai_content.setObjectName("ai-text")
            ai_content.setWordWrap(True)
            self.detail_layout.addWidget(ai_content)

        del_btn = QPushButton("Delete Record")
        del_btn.setObjectName("btn-danger")
        del_btn.setFixedHeight(34)
        del_btn.clicked.connect(lambda: self._delete_record(record.get("id")))
        self.detail_layout.addWidget(del_btn)
        self.detail_layout.addStretch()

    def _delete_record(self, record_id):
        if record_id is None:
            return
        reply = QMessageBox.question(self, "Delete", "Delete this record?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.db.delete_scan(record_id)
            self.refresh()

    def _clear_history(self):
        reply = QMessageBox.question(self, "Clear History",
            "Clear all scan history? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.db.clear_history()
            self.refresh()
