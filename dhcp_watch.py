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
MSG_TYPE_REQUEST = "Request"
MSG_TYPE_DISCOVER = "Discover"
UNKNOWN_VALUE = "unknown"
HTTP_USER_AGENT = "dhcp-watch/1.0"
MAC_VENDOR_API_BASE_URL = "https://api.macvendors.com"
TELEGRAM_API_BASE_URL = "https://api.telegram.org"
EXTERNAL_IP_LOOKUP_HOST = "ifconfig.me"
GEOLOCATION_LOOKUP_HOST = "ipinfo.io"

# Cache OUI prefix -> vendor name to avoid repeated API calls
_vendor_cache = {}

# Cache IP -> device type to avoid repeated nmap probes
_device_type_cache = {}

# Ports that reliably identify device types
_NMAP_PORT_DEVICE_MAP = {
    62078: "iPhone/iPad",   # iphone-sync (Apple wireless sync)
    7000: "AirPlay device", # Apple AirPlay
    548: "Mac",             # Apple Filing Protocol
    5009: "Apple TV",       # Apple TV remote
}


def probe_device_type(ip):
    """Use nmap to guess device type from open ports and OS fingerprint.

    Only called when MAC vendor lookup fails (e.g. randomised MAC).
    Results are cached by IP.
    """
    if not ip or ip == UNKNOWN_VALUE:
        return None
    if ip in _device_type_cache:
        return _device_type_cache[ip]

    device_type = None
    try:
        ports = ",".join(str(p) for p in _NMAP_PORT_DEVICE_MAP)
        result = subprocess.run(
            [
                "nmap", "-Pn", "-O", "--osscan-guess",
                "-T4", "--open",
                "-p", ports,
                ip,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout

        # Port matches are most reliable
        for port, dtype in _NMAP_PORT_DEVICE_MAP.items():
            if f"{port}/tcp" in output:
                device_type = dtype
                break

        # Fall back to OS fingerprint
        if not device_type:
            os_match = re.search(r"Aggressive OS guesses: ([^\n]+)", output)
            if os_match:
                guess = os_match.group(1).split("(")[0].strip().rstrip(",")
                if "iOS" in guess or "iPhone" in guess or "iPad" in guess:
                    device_type = "iPhone/iPad"
                elif "macOS" in guess or "Mac OS" in guess or "Darwin" in guess:
                    device_type = "Mac"
                elif "Android" in guess:
                    device_type = "Android"
                elif "Windows" in guess:
                    device_type = "Windows PC"
                elif "Linux" in guess:
                    device_type = "Linux"
                elif "Apple" in guess:
                    device_type = "Apple device"

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    _device_type_cache[ip] = device_type
    return device_type


def lookup_vendor(mac):
    """Look up the vendor for a MAC address using macvendors.com API.

    Caches results by OUI prefix (first 3 octets) so devices from the
    same manufacturer share a single lookup.
    """
    if not mac or mac == UNKNOWN_VALUE:
        return None
    oui = mac[:8].upper()  # e.g. "F0:81:73"
    if oui in _vendor_cache:
        return _vendor_cache[oui]
    try:
        url = f"{MAC_VENDOR_API_BASE_URL}/{urllib.parse.quote(oui)}"
        req = urllib.request.Request(url, headers={"User-Agent": HTTP_USER_AGENT})
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
    msg_type = None
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
            msg_type = MSG_TYPE_REQUEST
            continue

        # Check for DHCP Discover message type
        if discover_pattern.search(line):
            msg_type = MSG_TYPE_DISCOVER
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
                    "hostname": hostname or UNKNOWN_VALUE,
                    "ip": requested_ip or UNKNOWN_VALUE,
                    "mac": mac or UNKNOWN_VALUE,
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
    msg_type = packet_info.get("msg_type", MSG_TYPE_REQUEST)

    vendor = packet_info.get("vendor")
    device_type = packet_info.get("device_type")
    fields = [full_timestamp, f"{msg_type:8}"]
    if packet_info["hostname"] != UNKNOWN_VALUE:
        fields.append(f"Host: {packet_info['hostname']}")
    if packet_info["ip"] != UNKNOWN_VALUE:
        fields.append(f"IP: {packet_info['ip']}")
    if packet_info["mac"] != UNKNOWN_VALUE:
        mac_str = packet_info["mac"]
        label = vendor or device_type
        if label:
            mac_str += f" ({label})"
        fields.append(f"MAC: {mac_str}")
    output = " | ".join(fields)
    if suppressed:
        output += " [suppressed]"

    # Highlight DISCOVER packets in console output
    if use_color and msg_type == MSG_TYPE_DISCOVER:
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


def send_telegram_message(config, text):
    """Send a raw text message via Telegram."""
    url = f"{TELEGRAM_API_BASE_URL}/bot{config['bot_token']}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": config["chat_id"],
        "text": text,
    }).encode()
    try:
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"Failed to send Telegram message: {e}", file=sys.stderr)


def send_telegram_alert(config, packet_info, location=None):
    """Send a Telegram alert for a DHCP request."""
    today = datetime.now().strftime("%Y-%m-%d")
    ts = packet_info["timestamp"].split(".")[0]

    vendor = packet_info.get("vendor")
    device_type = packet_info.get("device_type")
    lines = []
    if location:
        lines.append(location)
    if packet_info["hostname"] != UNKNOWN_VALUE:
        lines.append(f"Hostname: {packet_info['hostname']}")
    if vendor:
        lines.append(f"Vendor: {vendor}")
    elif device_type:
        lines.append(f"Device: {device_type}")
    if packet_info["ip"] != UNKNOWN_VALUE:
        lines.append(f"IP: {packet_info['ip']}")
    if packet_info["mac"] != UNKNOWN_VALUE:
        lines.append(f"MAC: {packet_info['mac']}")
    lines.append(f"Time: {today} {ts}")
    message = "\n".join(lines)

    send_telegram_message(config, message)


def get_external_ip(ipv6=False):
    """Fetch external IP address using ifconfig.me."""
    try:
        cmd = ["curl", "-s", "-m", "5"]
        if not ipv6:
            cmd.append("-4")
        cmd.append(EXTERNAL_IP_LOOKUP_HOST)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def get_geolocation():
    """Fetch geolocation info using ipinfo.io."""
    try:
        cmd = ["curl", "-s", "-m", "5", GEOLOCATION_LOOKUP_HOST]
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
        city = geo.get("city", UNKNOWN_VALUE)
        country = geo.get("country", UNKNOWN_VALUE)
        loc = geo.get("loc", UNKNOWN_VALUE)
        location = f"{city}, {country} ({loc})"
        print(f"Location: {location}")

    if config:
        startup_lines = ["DHCP Watch started"]
        if ext_ipv4:
            startup_lines.append(f"IPv4: {ext_ipv4}")
        if ext_ipv6 and ext_ipv6 != ext_ipv4:
            startup_lines.append(f"IPv6: {ext_ipv6}")
        if location:
            startup_lines.append(f"Location: {location}")
        send_telegram_message(config, "\n".join(startup_lines))

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
                if not packet["vendor"] and packet["ip"] != UNKNOWN_VALUE:
                    packet["device_type"] = probe_device_type(packet["ip"])
                else:
                    packet["device_type"] = None
                output = format_output(packet, suppressed=suppressed, use_color=True)
                print(output)

                if suppressed:
                    continue

                log_file.write(format_output(packet, use_color=False) + "\n")
                log_file.flush()

                if config and packet["msg_type"] in [MSG_TYPE_DISCOVER, MSG_TYPE_REQUEST]:
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
