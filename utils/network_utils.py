import socket
import subprocess
import re
import struct


def get_default_gateway() -> tuple[str, str]:
    """Return (gateway_ip, interface_ip) by parsing 'route print'."""
    try:
        out = subprocess.check_output("route print 0.0.0.0", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2], parts[3]
    except Exception:
        pass
    return "", ""


def get_current_ssid() -> str:
    """Return the SSID of the currently connected Wi-Fi network."""
    try:
        out = subprocess.check_output(
            "netsh wlan show interfaces", shell=True, text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            if "SSID" in line and "BSSID" not in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip()
    except Exception:
        pass
    return "未知网络"


def get_current_bssid() -> str:
    """Return the BSSID of the connected AP."""
    try:
        out = subprocess.check_output(
            "netsh wlan show interfaces", shell=True, text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            if "BSSID" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip()
    except Exception:
        pass
    return ""


def get_arp_cache() -> dict[str, str]:
    """Return {ip: mac} from the system ARP cache."""
    result = {}
    try:
        out = subprocess.check_output("arp -a", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0].strip()
                mac = parts[1].strip()
                if re.match(r"\d+\.\d+\.\d+\.\d+", ip) and re.match(r"([0-9a-f]{2}-){5}[0-9a-f]{2}", mac, re.I):
                    result[ip] = mac.lower().replace("-", ":")
    except Exception:
        pass
    return result


def is_private_ip(ip: str) -> bool:
    try:
        packed = struct.unpack("!I", socket.inet_aton(ip))[0]
        ranges = [
            (0xC0A80000, 0xFFFF0000),  # 192.168.0.0/16
            (0xAC100000, 0xFFF00000),  # 172.16.0.0/12
            (0x0A000000, 0xFF000000),  # 10.0.0.0/8
        ]
        return any((packed & mask) == net for net, mask in ranges)
    except Exception:
        return False


def resolve_domain(domain: str, dns_server: str = "", timeout: int = 3) -> list[str]:
    """Resolve domain using a specific DNS server via dig-less approach (UDP socket)."""
    if not dns_server:
        try:
            return list({addr[4][0] for addr in socket.getaddrinfo(domain, None)})
        except Exception:
            return []

    import struct
    import random

    def build_query(domain: str, qid: int) -> bytes:
        header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        qname = b""
        for part in domain.split("."):
            encoded = part.encode()
            qname += bytes([len(encoded)]) + encoded
        qname += b"\x00"
        question = qname + struct.pack("!HH", 1, 1)
        return header + question

    def parse_response(data: bytes) -> list[str]:
        ips = []
        try:
            ancount = struct.unpack("!H", data[6:8])[0]
            offset = 12
            for _ in range(struct.unpack("!H", data[4:6])[0]):
                while offset < len(data) and data[offset] != 0:
                    offset += data[offset] + 1
                offset += 5
            for _ in range(ancount):
                if offset + 2 > len(data):
                    break
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(data) and data[offset] != 0:
                        offset += data[offset] + 1
                    offset += 1
                if offset + 10 > len(data):
                    break
                rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
                offset += 10
                if rtype == 1 and rdlength == 4:
                    ip = ".".join(str(b) for b in data[offset:offset + 4])
                    ips.append(ip)
                offset += rdlength
        except Exception:
            pass
        return ips

    try:
        qid = random.randint(0, 65535)
        query = build_query(domain, qid)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (dns_server, 53))
        data, _ = sock.recvfrom(512)
        sock.close()
        return parse_response(data)
    except Exception:
        return []


def check_internet(host: str = "8.8.8.8", port: int = 53, timeout: int = 3) -> bool:
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except Exception:
        return False
