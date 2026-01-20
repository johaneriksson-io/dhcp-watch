#!/usr/bin/env python3
"""
DHCP Watch - Monitor DHCP Request packets and log device information.

Captures DHCP Request packets via tcpdump and extracts hostname, IP address,
MAC address, and timestamp information.
"""

import subprocess
import sys
import re
from datetime import datetime

LOG_FILE = "/tmp/dhcp_watch.log"
INTERFACE = "any"


def parse_tcpdump_output(process):
    """Parse tcpdump output line by line using a state machine."""
    # State for current packet being parsed
    timestamp = None
    is_request = False
    mac = None
    requested_ip = None
    hostname = None

    # Regex patterns
    timestamp_pattern = re.compile(r"^(\d{2}:\d{2}:\d{2}\.\d+)\s+IP")
    request_pattern = re.compile(r"DHCP-Message.*Request")
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
            is_request = False
            mac = None
            requested_ip = None
            hostname = None
            continue

        # Check for DHCP Request message type
        if request_pattern.search(line):
            is_request = True
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
            if is_request and timestamp:
                yield {
                    "timestamp": timestamp,
                    "hostname": hostname or "unknown",
                    "ip": requested_ip or "unknown",
                    "mac": mac or "unknown",
                }
            # Reset for next packet
            timestamp = None
            is_request = False
            mac = None
            requested_ip = None
            hostname = None


def format_output(packet_info):
    """Format packet info for logging/display."""
    today = datetime.now().strftime("%Y-%m-%d")
    ts = packet_info["timestamp"].split(".")[0]  # Remove microseconds
    full_timestamp = f"{today} {ts}"

    return (
        f"{full_timestamp} | "
        f"Host: {packet_info['hostname']} | "
        f"IP: {packet_info['ip']} | "
        f"MAC: {packet_info['mac']}"
    )


def main():
    """Main entry point."""
    print(f"Starting DHCP watch on interface '{INTERFACE}'...")
    print(f"Logging to: {LOG_FILE}")
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
                output = format_output(packet)
                print(output)
                log_file.write(output + "\n")
                log_file.flush()

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
