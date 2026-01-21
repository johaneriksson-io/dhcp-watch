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
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime

LOG_FILE = "/tmp/dhcp_watch.log"
DEBOUNCE_SECONDS = 300  # 5 minutes
INTERFACE = "any"
CONFIG_FILE = Path(__file__).parent / "config.json"


def parse_tcpdump_output(process):
    """Parse tcpdump output line by line using a state machine."""
    # State for current packet being parsed
    timestamp = None
    msg_type = None  # "Request" or "Discover"
    mac = None
    requested_ip = None
    hostname = None

    # Regex patterns
    timestamp_pattern = re.compile(r"^(\d{2}:\d{2}:\d{2}\.\d+)\s+IP")
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

    output = (
        f"{full_timestamp} | "
        f"{msg_type:8} | "
        f"Host: {packet_info['hostname']} | "
        f"IP: {packet_info['ip']} | "
        f"MAC: {packet_info['mac']}"
    )
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


def send_telegram_alert(config, packet_info):
    """Send a Telegram alert for a DHCP request."""
    today = datetime.now().strftime("%Y-%m-%d")
    ts = packet_info["timestamp"].split(".")[0]

    message = (
        f"DHCP: {packet_info['hostname']}\n"
        f"IP: {packet_info['ip']}\n"
        f"Time: {today} {ts}\n"
        f"MAC: {packet_info['mac']}"
    )

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
    print("Press Ctrl+C to stop.\n")

    cmd = [
        "sudo",
        "tcpdump",
        "-i", INTERFACE,
        "port", "67", "or", "port", "68",
        "-n",
        "-vvv",
        "-l",  # Line-buffered output
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        with open(LOG_FILE, "a") as log_file:
            for packet in parse_tcpdump_output(process):
                mac = packet["mac"]
                now = time.time()
                last_seen = mac_last_seen.get(mac)
                suppressed = last_seen is not None and (now - last_seen) < DEBOUNCE_SECONDS

                output = format_output(packet, suppressed=suppressed, use_color=True)
                print(output)

                if packet["hostname"] == "Watch":
                    continue

                if suppressed:
                    continue

                mac_last_seen[mac] = now
                log_file.write(format_output(packet, use_color=False) + "\n")
                log_file.flush()

                if config:
                    send_telegram_alert(config, packet)

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
