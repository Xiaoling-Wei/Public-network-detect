# 公共网络安全检测工具

基于 Python + PyQt6 + Claude AI 的 Windows 桌面应用，用于检测公共 Wi-Fi 网络的安全风险。

## 功能

| 检测项 | 说明 |
|--------|------|
| ARP 欺骗检测 | 检测网关 MAC 是否被伪造（中间人攻击） |
| DNS 劫持检测 | 对比本地 DNS 与可信 DNS 解析结果 |
| SSL/TLS 检测 | 验证 HTTPS 证书有效性和 TLS 版本 |
| 威胁情报查询 | 通过 AbuseIPDB 检查网关/DNS IP 声誉 |
| AI 综合分析 | 使用 Claude AI 解读风险并给出建议 |

## 快速开始

### 1. 安装依赖

双击运行 `install.bat`，或手动执行：

```
pip install -r requirements.txt
```

### 2. 安装 Npcap（ARP 检测必需）

下载并安装：https://npcap.com/#download

安装时勾选 **WinPcap API-compatible mode**

### 3. 配置 API Key

启动程序后，进入 **设置** 页面：

- **Claude API Key**：用于 AI 分析，在 [console.anthropic.com](https://console.anthropic.com) 获取
- **AbuseIPDB Key**：用于威胁情报，在 [abuseipdb.com](https://www.abuseipdb.com) 免费注册获取

### 4. 启动程序

双击 `run.bat` 或运行：

```
python main.py
```

> **注意**：ARP 检测需要管理员权限。以管理员身份运行可获得更完整的检测结果。

## 打包为 EXE

```
双击 build.bat
```

生成的 EXE 位于 `dist\` 目录。

## 项目结构

```
├── main.py                 # 程序入口
├── core/
│   ├── scanner.py          # 扫描引擎（QThread）
│   ├── arp_detector.py     # ARP 欺骗检测
│   ├── dns_checker.py      # DNS 劫持检测
│   ├── ssl_checker.py      # SSL/TLS 检测
│   └── threat_intel.py     # 威胁情报
├── ai/
│   ├── analyzer.py         # Claude API 集成
│   └── ai_worker.py        # AI QThread 包装
├── ui/
│   ├── main_window.py      # 主窗口
│   ├── dashboard.py        # 仪表盘页
│   ├── scan_panel.py       # 扫描页
│   ├── history_view.py     # 历史页
│   ├── settings_view.py    # 设置页
│   └── widgets.py          # 共享组件
├── db/
│   └── database.py         # SQLite 存储
├── utils/
│   ├── network_utils.py    # 网络工具函数
│   └── windows_utils.py    # Windows API
└── assets/
    └── styles/
        └── dark_theme.qss  # 深色主题样式
```

## 依赖

- Python 3.11+
- PyQt6
- Scapy + Npcap
- Anthropic SDK
- Requests
- pywin32
