import sys
import os

# Add project root to path so all imports resolve correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon

from db.database import Database
from ui.main_window import MainWindow


def load_stylesheet(app: QApplication):
    qss_path = os.path.join(os.path.dirname(__file__), "assets", "styles", "dark_theme.qss")
    if os.path.exists(qss_path):
        with open(qss_path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())


def main():
    # High DPI support
    app = QApplication(sys.argv)
    app.setApplicationName("Public Network Security Scanner")
    app.setApplicationDisplayName("Public Network Security Scanner")
    app.setOrganizationName("SecurityDetector")

    load_stylesheet(app)

    db = Database()

    window = MainWindow(db)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
