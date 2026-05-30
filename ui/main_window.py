from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QStackedWidget, QStatusBar, QFrame
)
from PyQt6.QtCore import Qt

from db.database import Database


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
        self._navigate(0)

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
        self.status_bar.showMessage("Ready")

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

        nav_items = [
            ("📊", "Dashboard"),
            ("🔍", "Scan"),
            ("📋", "History"),
            ("⚙️", "Settings"),
        ]
        self.nav_buttons = []
        for icon, label in nav_items:
            btn = SidebarButton(icon, label)
            btn.clicked.connect(lambda _, i=len(self.nav_buttons): self._navigate(i))
            self.nav_buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch()
        ver = QLabel("v1.0.0")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver.setStyleSheet("color: #3a4560; font-size: 11px; padding: 8px;")
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

        self.stack.addWidget(self.dashboard_page)   # 0
        self.stack.addWidget(self.scan_page)         # 1
        self.stack.addWidget(self.history_page)      # 2
        self.stack.addWidget(self.settings_page)     # 3

        self.dashboard_page.navigate_to_scan.connect(lambda: self._navigate(1))
        self.scan_page.scan_saved.connect(self.history_page.refresh)
        self.scan_page.scan_saved.connect(self.dashboard_page.refresh_last_scan)
        self.scan_page.request_navigate.connect(self._navigate)

    def _navigate(self, index: int):
        self._active_index = index
        self.stack.setCurrentIndex(index)
        labels = ["Dashboard", "Scan", "History", "Settings"]
        for i, btn in enumerate(self.nav_buttons):
            btn.set_active(i == index)
        if 0 <= index < len(labels):
            self.status_bar.showMessage(labels[index])

    def set_status(self, message: str):
        self.status_bar.showMessage(message)

    def closeEvent(self, event):
        self.db.close()
        event.accept()
