#!/usr/bin/env python3
"""
DHCP Watch - Monitor DHCP Request packets and log device information.

Captures DHCP Request packets via tcpdump and extracts hostname, IP address,
MAC address, and timestamp information.
"""

import subprocess
import sys
import re
import json
import time
import os
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime

LOG_FILE = "/tmp/dhcp_watch.log"
DEBOUNCE_SECONDS = 300  # 5 minutes
INTERFACE = "any"
TCPDUMP_CMD = "tcpdump"
CONFIG_FILE = Path(__file__).parent / "config.json"

# Cache OUI prefix -> vendor name to avoid repeated API calls
_vendor_cache = {}


def lookup_vendor(mac):
    """Look up the vendor for a MAC address using macvendors.com API.

    Caches results by OUI prefix (first 3 octets) so devices from the
    same manufacturer share a single lookup.
    """
    if not mac or mac == "unknown":
        return None
    oui = mac[:8].upper()  # e.g. "F0:81:73"
    if oui in _vendor_cache:
        return _vendor_cache[oui]
    try:
        url = f"https://api.macvendors.com/{urllib.parse.quote(oui)}"
        req = urllib.request.Request(url, headers={"User-Agent": "dhcp-watch/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            vendor = response.read().decode().strip()
    except Exception:
        vendor = None
    _vendor_cache[oui] = vendor
    return vendor


def parse_tcpdump_output(process):
    """Parse tcpdump output line by line using a state machine."""
    # State for current packet being parsed
    timestamp = None
    msg_type = None  # "Request" or "Discover"
    mac = None
    requested_ip = None
    hostname = None

    # Regex patterns
    # Linux/macOS tcpdump can emit either:
    #   "11:45:41.796498 IP ..."
    #   "11:45:41.957616 wlan0 B   IP ..."
    timestamp_pattern = re.compile(
        r"^(\d{2}:\d{2}:\d{2}\.\d+)\s+(?:\S+\s+[BI]\s+)?IP\b"
    )
    request_pattern = re.compile(r"DHCP-Message.*Request")
    discover_pattern = re.compile(r"DHCP-Message.*Discover")
    mac_pattern = re.compile(r"Client-Ethernet-Address\s+([0-9a-f:]+)", re.IGNORECASE)
    ip_pattern = re.compile(r"Requested-IP.*?:\s*(\d+\.\d+\.\d+\.\d+)")
    hostname_pattern = re.compile(r'Hostname.*?:\s*"([^"]+)"')
    end_pattern = re.compile(r"END\s*\(255\)")

    for line in iter(process.stdout.readline, ""):
        line = line.strip()
        if not line:
            continue
        # Check for new packet (starts with timestamp)
        ts_match = timestamp_pattern.match(line)
        if ts_match:
            # New packet - reset state
            timestamp = ts_match.group(1)
            msg_type = None
            mac = None
            requested_ip = None
            hostname = None
            continue

        # Check for DHCP Request message type
        if request_pattern.search(line):
            msg_type = "Request"
            continue

        # Check for DHCP Discover message type
        if discover_pattern.search(line):
            msg_type = "Discover"
            continue

        # Extract MAC address
        mac_match = mac_pattern.search(line)
        if mac_match:
            mac = mac_match.group(1)
            continue

        # Extract Requested IP
        ip_match = ip_pattern.search(line)
        if ip_match:
            requested_ip = ip_match.group(1)
            continue

        # Extract Hostname
        hostname_match = hostname_pattern.search(line)
        if hostname_match:
            hostname = hostname_match.group(1)
            continue

        # Check for end of packet
        if end_pattern.search(line):
            if msg_type and timestamp:
                yield {
                    "timestamp": timestamp,
                    "hostname": hostname or "unknown",
                    "ip": requested_ip or "unknown",
                    "mac": mac or "unknown",
                    "msg_type": msg_type,
                }
            # Reset for next packet
            timestamp = None
            msg_type = None
            mac = None
            requested_ip = None
            hostname = None


# ANSI color codes
YELLOW = "\033[93m"
RESET = "\033[0m"


def format_output(packet_info, suppressed=False, use_color=False):
    """Format packet info for logging/display."""
    today = datetime.now().strftime("%Y-%m-%d")
    ts = packet_info["timestamp"].split(".")[0]  # Remove microseconds
    full_timestamp = f"{today} {ts}"
    msg_type = packet_info.get("msg_type", "Request")

    vendor = packet_info.get("vendor")
    fields = [full_timestamp, f"{msg_type:8}"]
    if packet_info["hostname"] != "unknown":
        fields.append(f"Host: {packet_info['hostname']}")
    if packet_info["ip"] != "unknown":
        fields.append(f"IP: {packet_info['ip']}")
    if packet_info["mac"] != "unknown":
        mac_str = packet_info["mac"]
        if vendor:
            mac_str += f" ({vendor})"
        fields.append(f"MAC: {mac_str}")
    output = " | ".join(fields)
    if suppressed:
        output += " [suppressed]"

    # Highlight DISCOVER packets in console output
    if use_color and msg_type == "Discover":
        output = f"{YELLOW}{output}{RESET}"

    return output


def load_config():
    """Load Telegram configuration from config file."""
    if not CONFIG_FILE.exists():
        return None
    try:
        with open(CONFIG_FILE) as f:
            config = json.load(f)
        if "bot_token" in config and "chat_id" in config:
            return config
        return None
    except (json.JSONDecodeError, IOError):
        return None


def send_telegram_alert(config, packet_info, location=None):
    """Send a Telegram alert for a DHCP request."""
    today = datetime.now().strftime("%Y-%m-%d")
    ts = packet_info["timestamp"].split(".")[0]

    vendor = packet_info.get("vendor")
    lines = []
    if location:
        lines.append(location)
    lines.append(f"Time: {today} {ts}")
    if packet_info["hostname"] != "unknown":
        lines.append(f"DHCP: {packet_info['hostname']}")
    if packet_info["ip"] != "unknown":
        lines.append(f"IP: {packet_info['ip']}")
    if packet_info["mac"] != "unknown":
        lines.append(f"MAC: {packet_info['mac']}")
    if vendor:
        lines.append(f"Vendor: {vendor}")
    message = "\n".join(lines)

    url = f"https://api.telegram.org/bot{config['bot_token']}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": config["chat_id"],
        "text": message,
    }).encode()

    try:
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"Failed to send Telegram alert: {e}", file=sys.stderr)


def get_external_ip(ipv6=False):
    """Fetch external IP address using ifconfig.me."""
    try:
        cmd = ["curl", "-s", "-m", "5"]
        if not ipv6:
            cmd.append("-4")
        cmd.append("ifconfig.me")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def get_geolocation():
    """Fetch geolocation info using ipinfo.io."""
    try:
        cmd = ["curl", "-s", "-m", "5", "ipinfo.io"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def main():
    """Main entry point."""
    config = load_config()
    mac_last_seen = {}  # Track last alert time per MAC for debouncing

    print(f"Starting DHCP watch on interface '{INTERFACE}'...")
    print(f"Logging to: {LOG_FILE}")
    print(f"Debounce: {DEBOUNCE_SECONDS}s per MAC")
    if config:
        print("Telegram alerts: enabled")
    else:
        print(f"Telegram alerts: disabled (configure in {CONFIG_FILE})")

    # Display external IP addresses and geolocation
    ext_ipv4 = get_external_ip(ipv6=False)
    ext_ipv6 = get_external_ip(ipv6=True)
    geo = get_geolocation()
    if ext_ipv4:
        print(f"External IPv4: {ext_ipv4}")
    if ext_ipv6:
        print(f"External IPv6: {ext_ipv6}")
    location = None
    if geo:
        city = geo.get("city", "unknown")
        country = geo.get("country", "unknown")
        loc = geo.get("loc", "unknown")
        location = f"{city}, {country} ({loc})"
        print(f"Location: {location}")

    print("Press Ctrl+C to stop.\n")

    cmd = [
        TCPDUMP_CMD,
        "-i", INTERFACE,
        "port", "67", "or", "port", "68",
        "-n",
        "-vvv",
        "-l",  # Line-buffered output
    ]

    if os.geteuid() != 0:
        print("Warning: not running as root.")
        print(
            "tcpdump may fail without privileges. "
            "Try: sudo python3 dhcp_watch.py"
        )

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        with open(LOG_FILE, "a") as log_file:
            for packet in parse_tcpdump_output(process):
                mac = packet["mac"]
                now = time.time()
                last_seen = mac_last_seen.get(mac)
                suppressed = last_seen is not None and (now - last_seen) < DEBOUNCE_SECONDS
                mac_last_seen[mac] = now

                packet["vendor"] = lookup_vendor(mac)
                output = format_output(packet, suppressed=suppressed, use_color=True)
                print(output)

                if suppressed:
                    continue

                log_file.write(format_output(packet, use_color=False) + "\n")
                log_file.flush()

                if config and packet["msg_type"] == "Discover":
                    send_telegram_alert(config, packet, location=location)

    except KeyboardInterrupt:
        print("\nStopping DHCP watch...")
        process.terminate()
        sys.exit(0)
    except FileNotFoundError:
        print("Error: tcpdump not found. Please install it.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print("Error: Permission denied. Run with sudo.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
