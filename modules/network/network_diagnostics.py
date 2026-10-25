import os
import re
import socket
import subprocess
from urllib.parse import urlparse


COMMON_TCP_PORTS = (
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (465, "SMTPS"),
    (587, "SMTP submission"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "Microsoft SQL Server"),
    (1521, "Oracle Database"),
    (2375, "Docker API"),
    (3000, "Development web server"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (5900, "VNC"),
    (6379, "Redis"),
    (8000, "Development web server"),
    (8080, "HTTP alternate"),
    (8443, "HTTPS alternate"),
    (9200, "Elasticsearch"),
    (11211, "Memcached"),
    (27017, "MongoDB"),
)

PING_COUNT = 4
CONNECT_TIMEOUT_SECONDS = 0.4


def _get_hostname(target):
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Please enter a valid target URL.")

    value = target.strip()
    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS website URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not supported.")
    return parsed.hostname


def check_open_ports(target):
    """Check a fixed list of common TCP ports on one resolved target IP."""
    try:
        hostname = _get_hostname(target)
        address_records = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
        resolved_ips = list(dict.fromkeys(
            record[4][0] for record in address_records
        ))
        if not resolved_ips:
            raise socket.gaierror("The host did not resolve to an IP address.")

        # A single address keeps this check bounded and makes the scanned
        # endpoint explicit in the result (CDNs may return edge addresses).
        scanned_ip = resolved_ips[0]
        open_ports = []

        for port, service in COMMON_TCP_PORTS:
            try:
                with socket.create_connection(
                    (scanned_ip, port),
                    timeout=CONNECT_TIMEOUT_SECONDS,
                ):
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "state": "Open",
                    })
            except (OSError, TimeoutError):
                continue

        return {
            "module": "Open Port Check",
            "target": target,
            "hostname": hostname,
            "scanned_ip": scanned_ip,
            "resolved_ips": resolved_ips,
            "ports_checked": len(COMMON_TCP_PORTS),
            "open_ports": open_ports,
            "summary": (
                f"{len(open_ports)} open port(s) found among "
                f"{len(COMMON_TCP_PORTS)} common TCP ports."
            ),
            "limitations": (
                "This checks only the listed public TCP ports on one resolved IP. "
                "A CDN or hosting provider may hide the origin server; "
                "closed and filtered ports cannot always be distinguished."
            ),
            "error": None,
        }

    except (ValueError, OSError) as error:
        return {
            "module": "Open Port Check",
            "target": str(target),
            "hostname": None,
            "scanned_ip": None,
            "resolved_ips": [],
            "ports_checked": 0,
            "open_ports": [],
            "summary": "The port check could not complete.",
            "limitations": (
                "Only run this check against a website or server you own "
                "or are authorized to assess."
            ),
            "error": str(error),
        }


def _parse_ping_results(output, sent_fallback):
    received = None

    windows_summary = re.search(
        r"Sent\s*=\s*(\d+)\s*,\s*Received\s*=\s*(\d+)",
        output,
        re.IGNORECASE,
    )
    if windows_summary:
        sent = int(windows_summary.group(1))
        received = int(windows_summary.group(2))
    else:
        unix_summary = re.search(
            r"(\d+)\s+packets transmitted\s*,\s*(\d+)\s+"
            r"(?:packets\s+)?received",
            output,
            re.IGNORECASE,
        )
        if unix_summary:
            sent = int(unix_summary.group(1))
            received = int(unix_summary.group(2))
        else:
            sent = sent_fallback
            received = sum(
                1
                for line in output.splitlines()
                if re.search(r"TTL\s*=|bytes from", line, re.IGNORECASE)
            )

    latencies = []
    for match in re.finditer(
        r"time\s*[=<]\s*(<\s*1|\d+(?:[.,]\d+)?)\s*ms",
        output,
        re.IGNORECASE,
    ):
        value = match.group(1).replace(",", ".").replace(" ", "")
        latencies.append(0.5 if value.startswith("<") else float(value))

    sent = max(0, sent)
    received = min(max(0, received), sent)
    return sent, received, latencies


def check_packet_loss(target):
    """Send four ICMP echo requests and summarize loss and round-trip time."""
    try:
        hostname = _get_hostname(target)
        if os.name == "nt":
            command = ["ping", "-n", str(PING_COUNT), "-w", "1200", hostname]
            timeout = 9
        else:
            command = ["ping", "-c", str(PING_COUNT), "-W", "2", hostname]
            timeout = 12

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        output = (completed.stdout or "") + "\n" + (completed.stderr or "")
        sent, received, latencies = _parse_ping_results(output, PING_COUNT)

        packet_loss = (
            round((sent - received) * 100 / sent, 1)
            if sent
            else None
        )
        if received == 0:
            interpretation = (
                "No ICMP replies were received. The host may block ping; "
                "this alone does not mean the website is unavailable."
            )
        elif packet_loss:
            interpretation = (
                "Some ICMP requests did not receive replies. Network filtering "
                "or temporary packet loss may affect this result."
            )
        else:
            interpretation = (
                "All ICMP requests received replies. This is a basic reachability "
                "check and does not inspect website request contents."
            )

        latency = {
            "minimum_ms": min(latencies) if latencies else None,
            "average_ms": (
                round(sum(latencies) / len(latencies), 2)
                if latencies else None
            ),
            "maximum_ms": max(latencies) if latencies else None,
        }

        return {
            "module": "Packet Loss / Latency Check",
            "target": target,
            "hostname": hostname,
            "packets_sent": sent,
            "responses_received": received,
            "packet_loss_percent": packet_loss,
            "latency": latency,
            "interpretation": interpretation,
            "limitations": (
                "This uses ICMP ping only. It cannot detect malformed or "
                "incorrect website data packets; inspect an authorized packet "
                "capture for that."
            ),
            "error": None,
        }

    except (ValueError, OSError, subprocess.SubprocessError) as error:
        return {
            "module": "Packet Loss / Latency Check",
            "target": str(target),
            "hostname": None,
            "packets_sent": 0,
            "responses_received": 0,
            "packet_loss_percent": None,
            "latency": {
                "minimum_ms": None,
                "average_ms": None,
                "maximum_ms": None,
            },
            "interpretation": "The network diagnostic could not complete.",
            "limitations": (
                "This uses ICMP ping only and does not inspect website data packets."
            ),
            "error": str(error),
        }
