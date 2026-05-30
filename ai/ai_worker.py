"""QThread wrapper for the AI analysis call."""

from PyQt6.QtCore import QThread, pyqtSignal
from ai.analyzer import analyze_with_ai


class AIWorker(QThread):
    analysis_done = pyqtSignal(dict)
    analysis_error = pyqtSignal(str)

    def __init__(self, scan_summary: dict, provider: str, api_key: str, model: str, parent=None):
        super().__init__(parent)
        self.scan_summary = scan_summary
        self.provider = provider
        self.api_key = api_key
        self.model = model

    def run(self):
        try:
            result = analyze_with_ai(self.scan_summary, self.provider, self.api_key, self.model)
            self.analysis_done.emit(result)
        except Exception as e:
            self.analysis_error.emit(str(e))
