"""Shared reusable UI components."""

from PyQt6.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QLabel, QFrame
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPainter, QColor, QFont

STATUS_ICONS = {
    "safe":    ("✅", "#4caf50", "Safe"),
    "warning": ("⚠️", "#ff9800", "Warning"),
    "danger":  ("❌", "#f44336", "Danger"),
    "unknown": ("❓", "#607d8b", "Unknown"),
}

RISK_COLORS = {
    "Safe":        "#4caf50",
    "Low Risk":    "#8bc34a",
    "Medium Risk": "#ff9800",
    "High Risk":   "#f44336",
    "Critical":    "#b71c1c",
}


class CheckResultItem(QFrame):
    def __init__(self, check_name: str, status: str, detail: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("check-item")
        self.setProperty("status", status)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(3)

        icon, color, label = STATUS_ICONS.get(status, ("❓", "#607d8b", "Unknown"))

        top_row = QHBoxLayout()
        name_lbl = QLabel(check_name)
        name_lbl.setObjectName("check-name")

        status_lbl = QLabel(f"{icon} {label}")
        status_lbl.setObjectName("check-status-text")
        status_lbl.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 12px;")
        status_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)

        top_row.addWidget(name_lbl)
        top_row.addStretch()
        top_row.addWidget(status_lbl)
        layout.addLayout(top_row)

        if detail:
            detail_lbl = QLabel(detail)
            detail_lbl.setObjectName("check-detail")
            detail_lbl.setWordWrap(True)
            layout.addWidget(detail_lbl)

        self.style().unpolish(self)
        self.style().polish(self)


class ScoreWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0.0
        self._risk_level = "Not Scanned"
        self.setMinimumSize(200, 200)
        self.setMaximumSize(240, 240)

    def set_score(self, score: float, risk_level: str):
        self._score = score
        self._risk_level = risk_level
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        cx, cy = w // 2, h // 2
        r = min(w, h) // 2 - 14

        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QPen

        pen = QPen(QColor("#2a2f3d"), 12)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(cx - r, cy - r, 2 * r, 2 * r, -225 * 16, -270 * 16)

        color = self._score_color()
        pen2 = QPen(QColor(color), 12)
        pen2.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen2)
        span = int(-270 * 16 * (self._score / 10))
        painter.drawArc(cx - r, cy - r, 2 * r, 2 * r, -225 * 16, span)

        painter.setPen(QColor(color))
        painter.setFont(QFont("Segoe UI", 32, QFont.Weight.Bold))
        painter.drawText(0, cy - 30, w, 60, Qt.AlignmentFlag.AlignCenter, f"{self._score:.1f}")

        painter.setPen(QColor("#6b7a99"))
        painter.setFont(QFont("Segoe UI", 12))
        painter.drawText(0, cy + 15, w, 30, Qt.AlignmentFlag.AlignCenter, "/ 10")

        risk_color = RISK_COLORS.get(self._risk_level, "#8a96b0")
        painter.setPen(QColor(risk_color))
        painter.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        painter.drawText(0, cy + 42, w, 28, Qt.AlignmentFlag.AlignCenter, self._risk_level)

        painter.end()

    def _score_color(self) -> str:
        if self._score >= 8: return "#4caf50"
        if self._score >= 6: return "#8bc34a"
        if self._score >= 4: return "#ff9800"
        if self._score >= 2: return "#f44336"
        return "#b71c1c"


class InfoCard(QFrame):
    def __init__(self, label: str, value: str = "—", parent=None):
        super().__init__(parent)
        self.setObjectName("info-card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)
        self._label_w = QLabel(label)
        self._label_w.setObjectName("info-label")
        self._value_w = QLabel(value)
        self._value_w.setObjectName("info-value")
        layout.addWidget(self._label_w)
        layout.addWidget(self._value_w)

    def set_value(self, value: str):
        self._value_w.setText(value)
