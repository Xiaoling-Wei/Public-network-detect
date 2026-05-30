import subprocess
import os
import winreg


def get_network_adapters() -> list[dict]:
    """Return list of active network adapters with IP/MAC info."""
    adapters = []
    try:
        out = subprocess.check_output(
            "netsh interface ip show config", shell=True, text=True, stderr=subprocess.DEVNULL
        )
        current = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Configuration for interface"):
                if current:
                    adapters.append(current)
                current = {"name": line.split('"')[1] if '"' in line else line}
            elif "IP Address" in line and ":" in line:
                current["ip"] = line.split(":", 1)[1].strip()
            elif "Default Gateway" in line and ":" in line:
                gw = line.split(":", 1)[1].strip()
                if gw:
                    current["gateway"] = gw
        if current:
            adapters.append(current)
    except Exception:
        pass
    return adapters


def get_wifi_security_type() -> str:
    """Return Wi-Fi security type (WPA2, WPA3, Open, etc.)."""
    try:
        out = subprocess.check_output(
            "netsh wlan show interfaces", shell=True, text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            if "Authentication" in line or "认证" in line:
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "Unknown"


def get_wifi_signal_strength() -> int:
    """Return Wi-Fi signal strength as percentage 0-100."""
    try:
        out = subprocess.check_output(
            "netsh wlan show interfaces", shell=True, text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            if "Signal" in line:
                val = line.split(":", 1)[1].strip().replace("%", "")
                return int(val)
    except Exception:
        pass
    return 0


def get_dns_servers() -> list[str]:
    """Return configured DNS server IPs."""
    servers = []
    try:
        out = subprocess.check_output(
            "netsh interface ip show dns", shell=True, text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            line = line.strip()
            import re
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                servers.append(match.group(1))
    except Exception:
        pass
    return list(dict.fromkeys(servers))


def open_network_and_sharing():
    """Open Windows Network and Sharing Center."""
    os.system("control.exe /name Microsoft.NetworkAndSharingCenter")


def is_admin() -> bool:
    """Check if running with administrator privileges."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_as_admin(script_path: str):
    """Re-launch script with admin privileges."""
    import ctypes
    import sys
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script_path}"', None, 1
    )
