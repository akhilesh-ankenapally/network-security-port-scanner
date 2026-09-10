"""
Network Security Port Scanner - Core Engine
Designed for academic cybersecurity demonstrations.
Provides multithreaded TCP socket scanning, service resolution, and error handling.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_SERVICES = {
    20: "FTP-Data (File Transfer Protocol)",
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted text communications)",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    67: "DHCP (Dynamic Host Configuration)",
    68: "DHCP (Client)",
    69: "TFTP (Trivial FTP)",
    80: "HTTP (Hypertext Transfer Protocol)",
    88: "Kerberos Authentication",
    110: "POP3 (Post Office Protocol v3)",
    119: "NNTP (Network News Transfer)",
    123: "NTP (Network Time Protocol)",
    135: "MS-RPC (Microsoft RPC Endpoint)",
    137: "NetBIOS-NS (Name Service)",
    138: "NetBIOS-DGM (Datagram Service)",
    139: "NetBIOS-SSN (Session Service)",
    143: "IMAP (Internet Message Access Protocol)",
    161: "SNMP (Simple Network Management)",
    179: "BGP (Border Gateway Protocol)",
    194: "IRC (Internet Relay Chat)",
    389: "LDAP (Lightweight Directory Access)",
    443: "HTTPS (HTTP Secure / TLS)",
    445: "SMB (Server Message Block / NetBIOS)",
    465: "SMTPS (Secure SMTP)",
    514: "Syslog (System Logging)",
    587: "SMTP (Message Submission)",
    636: "LDAPS (Secure LDAP)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1080: "SOCKS Proxy",
    1433: "MS SQL Server",
    1521: "Oracle Database",
    2049: "NFS (Network File System)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5000: "UPnP / Dev Server (Flask)",
    5432: "PostgreSQL Database",
    5900: "VNC (Virtual Network Computing)",
    6379: "Redis Key-Value Store",
    8000: "HTTP Alternate / Dev Server",
    8080: "HTTP-Proxy / Alternate Web Server",
    8443: "HTTPS Alternate",
    8888: "HTTP Alternate / Web Admin",
    9000: "Web Service / SonarQube",
    9090: "Prometheus / Web Cockpit",
    9200: "Elasticsearch REST API",
    27017: "MongoDB Database",
}


def resolve_target(target_str: str):
    """
    Validates and resolves a target IP or hostname to an IPv4 address.
    Returns (ip, None) on success or (None, error_message) on failure.
    """
    cleaned = (target_str or "").strip()
    if not cleaned:
        return None, "Target host/IP address cannot be empty."

    # Remove protocol prefix if entered (e.g., http:// or https://)
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    if ":" in cleaned:
        cleaned = cleaned.split(":", 1)[0]

    try:
        ip = socket.gethostbyname(cleaned)
        return ip, None
    except socket.gaierror:
        return None, f"DNS resolution failed for '{cleaned}'. Hostname or IP is invalid or unreachable."
    except Exception as exc:
        return None, f"Failed to resolve target '{cleaned}': {str(exc)}"


def get_service_name(port: int) -> str:
    """Returns human-readable service name for a given port."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except (OSError, socket.error):
        return "Unknown / Custom Service"


def grab_banner(sock: socket.socket, port: int) -> str:
    """
    Attempts to read banner string from an open socket.
    Safe and non-blocking with short timeout.
    """
    try:
        sock.settimeout(0.3)
        if port in (80, 8080, 8000, 8888):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        elif port in (21, 22, 25, 110):
            # Many text protocols send a greeting banner upon connection
            pass
        else:
            return ""

        data = sock.recv(256)
        if data:
            cleaned = data.decode("utf-8", errors="ignore").strip()
            # Grab first meaningful line
            first_line = cleaned.splitlines()[0] if cleaned else ""
            return first_line[:60]
    except Exception:
        pass
    return ""


def scan_single_port(ip: str, port: int, timeout: float = 0.5) -> dict:
    """
    Scans a single TCP port using standard socket connect.
    Measures round-trip latency and grabs service banner if open.
    """
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    is_open = False
    banner = ""
    error_detail = None

    try:
        result_code = sock.connect_ex((ip, port))
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if result_code == 0:
            is_open = True
            banner = grab_banner(sock, port)
        else:
            error_detail = "Connection refused or timed out"
    except socket.timeout:
        latency_ms = round(timeout * 1000, 2)
        error_detail = "Timeout"
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        error_detail = str(exc)
    finally:
        sock.close()

    return {
        "port": port,
        "status": "OPEN" if is_open else "CLOSED",
        "service": get_service_name(port),
        "latency_ms": latency_ms,
        "banner": banner,
        "error": error_detail,
    }


def scan_ports(ip: str, ports: list[int], timeout: float = 0.5, max_workers: int = 60) -> dict:
    """
    Runs multithreaded scanning on the specified list of ports.
    Returns structured results and metrics.
    """
    scan_start = time.perf_counter()
    results = []

    workers = max(1, min(len(ports), max_workers))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(scan_single_port, ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            try:
                res = future.result()
                results.append(res)
            except Exception as exc:
                port = future_to_port[future]
                results.append({
                    "port": port,
                    "status": "CLOSED",
                    "service": get_service_name(port),
                    "latency_ms": 0.0,
                    "banner": "",
                    "error": str(exc),
                })

    # Sort results sequentially by port number
    results.sort(key=lambda item: item["port"])

    duration = round(time.perf_counter() - scan_start, 2)
    open_count = sum(1 for r in results if r["status"] == "OPEN")
    closed_count = len(results) - open_count

    return {
        "total_ports": len(ports),
        "open_count": open_count,
        "closed_count": closed_count,
        "duration_seconds": duration,
        "results": results,
    }


if __name__ == "__main__":
    # Quick self-test on localhost
    test_target = "127.0.0.1"
    print(f"Testing scanner engine against {test_target}...")
    ip, err = resolve_target(test_target)
    if err:
        print("Resolution error:", err)
    else:
        sample_ports = [21, 22, 80, 135, 443, 445, 3306, 5000, 8080]
        data = scan_ports(ip, sample_ports, timeout=0.3)
        print(f"Scanned {data['total_ports']} ports in {data['duration_seconds']}s")
        print(f"Open: {data['open_count']} | Closed: {data['closed_count']}")
        for r in data["results"]:
            if r["status"] == "OPEN":
                print(f"  [+] Port {r['port']} OPEN ({r['service']}) - {r['latency_ms']}ms")
