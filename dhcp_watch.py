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
import threading
import urllib.request
import urllib.parse
from datetime import datetime
from config_validator import (
    USER_CONFIG_FILE,
    load_and_validate_config,
    load_defaults,
)
from host_roster import HostRoster, seed_roster_from_log
from web_ui import start_web_server, stop_web_server

# Protocol vocabulary and display constants; everything tunable lives in
# config.default.json (overridable per host in config.json).
MSG_TYPE_REQUEST = "Request"
MSG_TYPE_DISCOVER = "Discover"
UNKNOWN_VALUE = "unknown"

# Grace added on top of a lookup's own timeout before the subprocess is killed,
# so curl gets the chance to time out and exit cleanly first.
SUBPROCESS_TIMEOUT_MARGIN_SECONDS = 5

# Cache OUI prefix -> vendor name to avoid repeated API calls
_vendor_cache = {}

# Cache IP -> device type to avoid repeated nmap probes
_device_type_cache = {}


def probe_device_type(ip, config=None):
    """Use nmap to guess device type from open ports and OS fingerprint.

    Only called when MAC vendor lookup fails (e.g. randomised MAC).
    Results are cached by IP.
    """
    config = config or load_defaults()
    if not ip or ip == UNKNOWN_VALUE:
        return None
    if ip in _device_type_cache:
        return _device_type_cache[ip]

    port_device_map = config.nmap_port_device_map
    device_type = None
    try:
        ports = ",".join(str(p) for p in port_device_map)
        result = subprocess.run(
            [
                "nmap", "-Pn", "-O", "--osscan-guess",
                "-T4", "--open",
                "-p", ports,
                ip,
            ],
            capture_output=True,
            text=True,
            timeout=config.nmap_timeout_seconds,
        )
        output = result.stdout

        # Port matches are most reliable
        for port, dtype in port_device_map.items():
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

    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass

    _device_type_cache[ip] = device_type
    return device_type


def lookup_vendor(mac, config=None):
    """Look up the vendor for a MAC address using macvendors.com API.

    Caches results by OUI prefix (first 3 octets) so devices from the
    same manufacturer share a single lookup.
    """
    config = config or load_defaults()
    if not mac or mac == UNKNOWN_VALUE:
        return None
    oui = mac[:8].upper()  # e.g. "F0:81:73"
    if oui in _vendor_cache:
        return _vendor_cache[oui]
    try:
        url = f"{config.mac_vendor_api_base_url}/{urllib.parse.quote(oui)}"
        req = urllib.request.Request(url, headers={"User-Agent": config.http_user_agent})
        with urllib.request.urlopen(req, timeout=config.vendor_lookup_timeout_seconds) as response:
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
    """Load config.default.json, then apply config.json overrides on top."""
    return load_and_validate_config(USER_CONFIG_FILE)


def send_telegram_message(config, text):
    """Send a raw text and message via Telegram."""
    url = f"{config.telegram_api_base_url}/bot{config.bot_token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": config.chat_id,
        "text": text,
    }).encode()
    try:
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=config.telegram_timeout_seconds)
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
        mac_str = packet_info["mac"]
        label = vendor or device_type
        if label:
            mac_str += f" ({label})"
        lines.append(f"MAC: {mac_str}")
    lines.append(f"Time: {today} {ts}")
    message = "\n".join(lines)

    send_telegram_message(config, message)

def get_external_ip(ipv6=False, config=None):
    """Fetch external IP address from the configured lookup host."""
    config = config or load_defaults()
    timeout = config.external_lookup_timeout_seconds
    try:
        cmd = ["curl", "-s", "-m", str(int(timeout))]
        if not ipv6:
            cmd.append("-4")
        cmd.append(config.external_ip_lookup_host)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + SUBPROCESS_TIMEOUT_MARGIN_SECONDS,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def get_geolocation(config=None):
    """Fetch geolocation info from the configured lookup host."""
    config = config or load_defaults()
    timeout = config.external_lookup_timeout_seconds
    try:
        cmd = ["curl", "-s", "-m", str(int(timeout)), config.geolocation_lookup_host]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + SUBPROCESS_TIMEOUT_MARGIN_SECONDS,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def is_hostname_ignored(hostname, ignored_hostnames):
    """Return True if the hostname is in the ignored list (case-insensitive)."""
    if not ignored_hostnames or hostname == UNKNOWN_VALUE:
        return False
    hostname_lower = hostname.lower()
    return any(h.lower() == hostname_lower for h in ignored_hostnames)


def is_mac_ignored(mac, ignored_macs):
    """Return True if the MAC address is in the ignored list (case-insensitive)."""
    if not ignored_macs or mac == UNKNOWN_VALUE:
        return False
    mac_lower = mac.lower()
    return any(m.lower() == mac_lower for m in ignored_macs)


def apply_packet_to_roster(roster, packet, last_seen=None):
    """Update the live roster from a parsed DHCP packet.

    Called for every detection, including debounce-suppressed ones, first
    before the vendor/nmap lookups so the UI is not gated on those, then again
    once they have answered so the page can show the manufacturer.
    """
    return roster.upsert(
        packet.get("mac"),
        packet.get("hostname"),
        packet.get("ip"),
        last_seen=last_seen,
        vendor=packet.get("vendor") or packet.get("device_type"),
    )


def start_aging_sweep(roster, stop_event, interval_seconds=None):
    """Background timer that ages hosts out even when the LAN is idle."""
    if interval_seconds is None:
        interval_seconds = load_defaults().aging_sweep_interval_seconds

    def _loop():
        while not stop_event.wait(interval_seconds):
            roster.expire_older_than()

    thread = threading.Thread(target=_loop, name="dhcp-watch-aging", daemon=True)
    thread.start()
    return thread


def main():
    """Main entry point."""
    config = load_config()
    mac_last_seen = {}  # Track last alert time per MAC for debouncing
    ignored_hostnames = config.ignored_hostnames
    ignored_macs = config.ignored_macs
    debounce_seconds = config.debounce_seconds
    log_file_path = config.log_file
    roster = HostRoster(quiet_period_seconds=config.quiet_period_seconds)
    web_stop_event = threading.Event()
    httpd = None

    print(f"Starting DHCP watch on interface '{config.interface}'...")
    print(f"Logging to: {log_file_path}")
    print(f"Debounce: {debounce_seconds}s per MAC")
    if config.telegram_enabled:
        print("Telegram alerts: enabled")
        if ignored_hostnames:
            print(f"Ignored hostnames: {', '.join(ignored_hostnames)}")
        if ignored_macs:
            print(f"Ignored MACs: {', '.join(ignored_macs)}")
    else:
        print(f"Telegram alerts: disabled (configure in {USER_CONFIG_FILE})")

    # Display external IP addresses and geolocation
    ext_ipv4 = get_external_ip(ipv6=False, config=config)
    ext_ipv6 = get_external_ip(ipv6=True, config=config)
    if ext_ipv4:
        print(f"External IPv4: {ext_ipv4}")
    if ext_ipv6:
        print(f"External IPv6: {ext_ipv6}")

    # Prefer a manually configured location; the geo IP lookup is approximate.
    location = None
    if config.location:
        location = config.location
        print(f"Location: {location} (from config)")
    else:
        geo = get_geolocation(config=config)
        if geo:
            city = geo.get("city", UNKNOWN_VALUE)
            country = geo.get("country", UNKNOWN_VALUE)
            loc = geo.get("loc", UNKNOWN_VALUE)
            location = f"{city}, {country} ({loc})"
            print(f"Location: {location}")

    seeded = seed_roster_from_log(roster, log_file_path)
    print(f"Live roster seed: {seeded} host(s) from log")

    bind_host = config.web_bind_host
    web_port = config.web_port
    try:
        httpd, _web_thread, web_stop_event = start_web_server(
            roster,
            host=bind_host,
            port=web_port,
            stop_event=web_stop_event,
            heartbeat_seconds=config.sse_heartbeat_seconds,
        )
    except OSError as e:
        print(f"Error: failed to bind web UI on {bind_host}:{web_port}: {e}", file=sys.stderr)
        sys.exit(1)

    print(
        f"Live hosts page: http://<this-host>:{web_port}/ "
        f"(bound {bind_host}:{web_port}, unauthenticated LAN access)"
    )
    print(
        "Note: the web UI runs in this process (often as root for capture); "
        "prefer tcpdump capabilities and host firewall limits when possible."
    )
    start_aging_sweep(roster, web_stop_event, config.aging_sweep_interval_seconds)

    if config.telegram_enabled:
        startup_lines = ["DHCP Watch started"]
        if ext_ipv4:
            startup_lines.append(f"IPv4: {ext_ipv4}")
        if ext_ipv6 and ext_ipv6 != ext_ipv4:
            startup_lines.append(f"IPv6: {ext_ipv6}")
        if location:
            startup_lines.append(f"Location: {location}")
        startup_lines.append(f"Live hosts: port {web_port}")
        send_telegram_message(config, "\n".join(startup_lines))

    print("Press Ctrl+C to stop.\n")

    cmd = [
        config.tcpdump_command,
        "-i", config.interface,
        "port", "67", "or", "port", "68",
        "-p",  # No promiscuous mode (not needed for DHCP, avoids warning on 'any')
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

    process = None
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        with open(log_file_path, "a") as log_file:
            for packet in parse_tcpdump_output(process):
                mac = packet["mac"]
                now = time.time()
                last_seen = mac_last_seen.get(mac)
                suppressed = last_seen is not None and (now - last_seen) < debounce_seconds
                mac_last_seen[mac] = now

                apply_packet_to_roster(roster, packet, last_seen=now)

                packet["vendor"] = lookup_vendor(mac, config)
                if not packet["vendor"] and packet["ip"] != UNKNOWN_VALUE:
                    packet["device_type"] = probe_device_type(packet["ip"], config)
                else:
                    packet["device_type"] = None
                # Second pass, now that the lookups have named the manufacturer.
                apply_packet_to_roster(roster, packet, last_seen=now)

                output = format_output(packet, suppressed=suppressed, use_color=True)
                print(output)

                if suppressed:
                    continue

                log_file.write(format_output(packet, use_color=False) + "\n")
                log_file.flush()

                if config.telegram_enabled and packet["msg_type"] in config.alert_on_message_types:
                    if not is_hostname_ignored(packet["hostname"], ignored_hostnames) and \
                            not is_mac_ignored(packet["mac"], ignored_macs):
                        send_telegram_alert(config, packet, location=location)

    except KeyboardInterrupt:
        print("\nStopping DHCP watch...")
        if process is not None:
            process.terminate()
        sys.exit(0)
    except FileNotFoundError:
        print("Error: tcpdump not found. Please install it.", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        import traceback
        traceback.print_exc()
        print(f"\nError: Permission denied: {e}", file=sys.stderr)
        print("Run with sudo.", file=sys.stderr)
        sys.exit(1)
    finally:
        if httpd is not None:
            stop_web_server(httpd, web_stop_event)


if __name__ == "__main__":
    main()
