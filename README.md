# Public Network Security Scanner

A Windows desktop application built with Python + PyQt6 for detecting security risks on public Wi-Fi networks, powered by AI analysis (OpenAI / Google Gemini / Anthropic Claude).

## Features

| Check | Description |
|-------|-------------|
| ARP Spoofing Detection | Detects forged gateway MAC addresses (man-in-the-middle attacks) |
| DNS Hijacking Detection | Compares local DNS responses against trusted resolvers (8.8.8.8, 1.1.1.1) |
| SSL/TLS Verification | Validates HTTPS certificate chains and TLS versions |
| Threat Intelligence | Checks gateway and DNS IPs against the AbuseIPDB database |
| AI Security Analysis | Plain-English risk summary and recommendations from your chosen AI provider |

## Quick Start

### 1. Install Dependencies

Double-click `install.bat`, or run manually:

```
pip install -r requirements.txt
```

### 2. Install Npcap (required for ARP detection)

Download and install from: https://npcap.com/#download

During installation, check **WinPcap API-compatible mode**.

### 3. Configure API Keys

Launch the app and go to the **Settings** page:

**AI Provider** — choose one and enter its key:
| Provider | Key source |
|----------|-----------|
| OpenAI (GPT-4o, GPT-4-turbo…) | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) |
| Google Gemini | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) |
| Anthropic Claude | [console.anthropic.com](https://console.anthropic.com/settings/keys) |

**AbuseIPDB** (optional) — free registration at [abuseipdb.com](https://www.abuseipdb.com)

### 4. Run

Double-click `run.bat` or:

```
python main.py
```

> **Note:** ARP detection requires administrator privileges for a full live probe. Run as Administrator for the most accurate results.

## Build as EXE

```
build.bat
```

The standalone `.exe` will be output to the `dist\` folder.

## Project Structure

```
├── main.py                   # Entry point
├── core/
│   ├── scanner.py            # Scan orchestrator (QThread)
│   ├── arp_detector.py       # ARP spoofing detection
│   ├── dns_checker.py        # DNS hijacking detection
│   ├── ssl_checker.py        # SSL/TLS certificate check
│   └── threat_intel.py       # AbuseIPDB threat intelligence
├── ai/
│   ├── providers.py          # Multi-provider abstraction (OpenAI / Gemini / Claude)
│   ├── analyzer.py           # AI analysis logic
│   └── ai_worker.py          # QThread wrapper for AI calls
├── ui/
│   ├── main_window.py        # Main window & sidebar navigation
│   ├── dashboard.py          # Dashboard page
│   ├── scan_panel.py         # Scan page
│   ├── history_view.py       # History page
│   ├── settings_view.py      # Settings page
│   └── widgets.py            # Shared UI components
├── db/
│   └── database.py           # SQLite scan history
├── utils/
│   ├── network_utils.py      # Network helper functions
│   └── windows_utils.py      # Windows API utilities
└── assets/
    └── styles/
        └── dark_theme.qss    # Dark theme stylesheet
```

## Requirements

- Python 3.11+
- PyQt6
- Scapy + [Npcap](https://npcap.com)
- openai
- google-generativeai
- anthropic
- requests
- pywin32
