from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QMessageBox,
    QScrollArea, QComboBox
)
from PyQt6.QtCore import Qt

from db.database import Database
from ai.providers import PROVIDER_CONFIG


class SettingsPage(QWidget):
    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()
        self._load_settings()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 20)
        outer.setSpacing(16)

        title = QLabel("Settings")
        title.setObjectName("page-title")
        outer.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(20)
        scroll.setWidget(content)

        # ── AI Provider ──────────────────────────────────────────────
        layout.addWidget(self._section("AI Provider"))
        layout.addWidget(self._hint(
            "Select the AI provider and enter the corresponding API key.\n"
            "The AI analyzes scan results and gives you plain-English recommendations."
        ))

        provider_row = QHBoxLayout()
        self.provider_combo = QComboBox()
        self.provider_combo.setStyleSheet(
            "QComboBox { background:#232838; color:#e0e6f0; border:1px solid #2a2f3d;"
            " border-radius:8px; padding:6px 12px; font-size:13px; }"
            "QComboBox::drop-down { border:none; }"
            "QComboBox QAbstractItemView { background:#1e2330; color:#e0e6f0;"
            " selection-background-color:#1e3a5f; }"
        )
        for key, cfg in PROVIDER_CONFIG.items():
            self.provider_combo.addItem(cfg["name"], key)
        self.provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        provider_row.addWidget(self.provider_combo)
        layout.addLayout(provider_row)

        # Model selector
        model_row = QHBoxLayout()
        model_lbl = QLabel("Model:")
        model_lbl.setStyleSheet("color:#8a96b0; font-size:12px; min-width:50px;")
        self.model_combo = QComboBox()
        self.model_combo.setStyleSheet(
            "QComboBox { background:#232838; color:#e0e6f0; border:1px solid #2a2f3d;"
            " border-radius:8px; padding:6px 12px; font-size:13px; }"
            "QComboBox::drop-down { border:none; }"
            "QComboBox QAbstractItemView { background:#1e2330; color:#e0e6f0;"
            " selection-background-color:#1e3a5f; }"
        )
        model_row.addWidget(model_lbl)
        model_row.addWidget(self.model_combo, stretch=1)
        layout.addLayout(model_row)

        # API Key
        layout.addWidget(self._hint("API Key for the selected provider:"))
        key_row = QHBoxLayout()
        self.ai_key_input = QLineEdit()
        self.ai_key_input.setPlaceholderText("Enter API key…")
        self.ai_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_row.addWidget(self.ai_key_input)

        toggle_ai = QPushButton("Show / Hide")
        toggle_ai.setObjectName("btn-secondary")
        toggle_ai.setMinimumWidth(100)
        toggle_ai.clicked.connect(lambda: self._toggle_echo(self.ai_key_input))
        key_row.addWidget(toggle_ai)
        layout.addLayout(key_row)

        # Key help links per provider
        self.key_hint_lbl = QLabel("")
        self.key_hint_lbl.setStyleSheet("color:#4fc3f7; font-size:11px;")
        self.key_hint_lbl.setOpenExternalLinks(True)
        layout.addWidget(self.key_hint_lbl)

        # ── AbuseIPDB ────────────────────────────────────────────────
        layout.addWidget(self._section("AbuseIPDB — Threat Intelligence"))
        layout.addWidget(self._hint(
            "Optional. Used to check if gateway and DNS IPs are flagged as malicious.\n"
            "Free at abuseipdb.com (Account → API)"
        ))

        abuse_row = QHBoxLayout()
        self.abuse_key_input = QLineEdit()
        self.abuse_key_input.setPlaceholderText("AbuseIPDB API Key (optional)")
        self.abuse_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        abuse_row.addWidget(self.abuse_key_input)

        toggle_abuse = QPushButton("Show/Hide")
        toggle_abuse.setObjectName("btn-secondary")
        toggle_abuse.setMinimumWidth(100)
        toggle_abuse.clicked.connect(lambda: self._toggle_echo(self.abuse_key_input))
        abuse_row.addWidget(toggle_abuse)
        layout.addLayout(abuse_row)

        # ── About ────────────────────────────────────────────────────
        layout.addWidget(self._section("About"))
        about = QFrame()
        about.setObjectName("info-card")
        about_layout = QVBoxLayout(about)
        about_layout.setSpacing(4)
        about_layout.addWidget(QLabel("Public Network Security Scanner  v1.0.0"))
        about_layout.addWidget(self._hint(
            "Detects ARP spoofing, DNS hijacking, SSL/TLS issues, and threat intelligence risks\n"
            "on public Wi-Fi networks.\n"
            "Built with Python · PyQt6 · OpenAI / Gemini / Claude"
        ))
        layout.addWidget(about)

        # Save button
        save_btn = QPushButton("Save Settings")
        save_btn.setObjectName("btn-primary")
        save_btn.setFixedHeight(40)
        save_btn.setFixedWidth(160)
        save_btn.clicked.connect(self._save_settings)
        layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addStretch()

    # ------------------------------------------------------------------

    def _section(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("section-title")
        return lbl

    def _hint(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("color: #6b7a99; font-size: 11px;")
        lbl.setWordWrap(True)
        return lbl

    def _toggle_echo(self, field: QLineEdit):
        field.setEchoMode(
            QLineEdit.EchoMode.Normal
            if field.echoMode() == QLineEdit.EchoMode.Password
            else QLineEdit.EchoMode.Password
        )

    def _on_provider_changed(self, _=None):
        provider_key = self.provider_combo.currentData()
        cfg = PROVIDER_CONFIG.get(provider_key, {})

        self.model_combo.clear()
        for m in cfg.get("models", []):
            self.model_combo.addItem(m)

        hints = {
            "openai": 'Get key at <a href="https://platform.openai.com/api-keys" style="color:#4fc3f7">platform.openai.com/api-keys</a>',
            "gemini": 'Get key at <a href="https://aistudio.google.com/apikey" style="color:#4fc3f7">aistudio.google.com/apikey</a>',
            "claude": 'Get key at <a href="https://console.anthropic.com/settings/keys" style="color:#4fc3f7">console.anthropic.com</a>',
        }
        self.key_hint_lbl.setText(hints.get(provider_key, ""))

        # Restore saved key for this provider
        saved_key = self.db.get_setting(f"ai_key_{provider_key}")
        self.ai_key_input.setText(saved_key)

    def _load_settings(self):
        # Set provider combo
        saved_provider = self.db.get_setting("ai_provider", "openai")
        for i in range(self.provider_combo.count()):
            if self.provider_combo.itemData(i) == saved_provider:
                self.provider_combo.setCurrentIndex(i)
                break
        self._on_provider_changed()  # populate models + key

        # Restore model
        saved_model = self.db.get_setting("ai_model")
        if saved_model:
            idx = self.model_combo.findText(saved_model)
            if idx >= 0:
                self.model_combo.setCurrentIndex(idx)

        self.abuse_key_input.setText(self.db.get_setting("abuse_api_key"))

    def _save_settings(self):
        provider_key = self.provider_combo.currentData()
        model        = self.model_combo.currentText()
        api_key      = self.ai_key_input.text().strip()

        self.db.set_setting("ai_provider", provider_key)
        self.db.set_setting("ai_model",    model)
        self.db.set_setting("ai_api_key",  api_key)
        self.db.set_setting(f"ai_key_{provider_key}", api_key)
        self.db.set_setting("abuse_api_key", self.abuse_key_input.text().strip())

        QMessageBox.information(self, "Saved", "Settings saved successfully.")
