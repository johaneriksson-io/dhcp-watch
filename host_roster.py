"""Thread-safe in-memory host roster for the live hosts web UI."""

from __future__ import annotations

import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from config_validator import load_defaults

UNKNOWN_MAC = "unknown"
UNKNOWN_VALUE = "unknown"
QUIET_PERIOD_SECONDS = load_defaults().quiet_period_seconds

_LOG_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*\|")
_LOG_HOST = re.compile(r"Host:\s*([^\|]+)")
_LOG_IP = re.compile(r"IP:\s*([^\|]+)")
_LOG_MAC = re.compile(r"MAC:\s*([0-9a-fA-F:]+)(?:\s*\(([^)]*)\))?")


def parse_log_line(line: str) -> dict[str, Any] | None:
    """Parse one dhcp_watch log line into a roster entry, or None if unusable."""
    line = line.strip()
    if not line:
        return None
    ts_match = _LOG_TIMESTAMP.match(line)
    mac_match = _LOG_MAC.search(line)
    if not ts_match or not mac_match:
        return None
    try:
        last_seen = datetime.strptime(ts_match.group(1), "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        return None

    host_match = _LOG_HOST.search(line)
    ip_match = _LOG_IP.search(line)
    hostname = host_match.group(1).strip() if host_match else UNKNOWN_VALUE
    ip = ip_match.group(1).strip() if ip_match else UNKNOWN_VALUE
    vendor = (mac_match.group(2) or "").strip()
    return {
        "mac": mac_match.group(1).lower(),
        "hostname": hostname or UNKNOWN_VALUE,
        "ip": ip or UNKNOWN_VALUE,
        "vendor": vendor or None,
        "last_seen": last_seen,
    }


def seed_roster_from_log(
    roster: "HostRoster",
    log_path: str | Path,
    *,
    now: float | None = None,
    quiet_period_seconds: int | None = None,
) -> int:
    """Seed roster from log entries still within the quiet period.

    Best-effort: missing/unreadable logs yield an empty seed. Seeded last_seen
    is the last *logged* sighting and may lag live detections by up to the
    debounce window because suppressed packets are not written to the log.
    """
    path = Path(log_path)
    if not path.is_file():
        return 0

    quiet = (
        roster.quiet_period_seconds
        if quiet_period_seconds is None
        else quiet_period_seconds
    )
    cutoff = (time.time() if now is None else now) - quiet
    best: dict[str, dict[str, Any]] = {}

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0

    for line in text.splitlines():
        entry = parse_log_line(line)
        if entry is None:
            continue
        if entry["last_seen"] <= cutoff:
            continue
        mac = entry["mac"]
        previous = best.get(mac)
        if previous is None or entry["last_seen"] > previous["last_seen"]:
            best[mac] = entry

    return roster.seed_from_entries(list(best.values()))


class HostRoster:
    """MAC-keyed host store with upsert, expire, snapshot, and change wait."""

    def __init__(self, quiet_period_seconds: int = QUIET_PERIOD_SECONDS):
        self._quiet_period_seconds = quiet_period_seconds
        self._hosts: dict[str, dict[str, Any]] = {}
        self._version = 0
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)

    @property
    def quiet_period_seconds(self) -> int:
        return self._quiet_period_seconds

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    def upsert(
        self,
        mac: str | None,
        hostname: str | None,
        ip: str | None,
        last_seen: float | None = None,
        vendor: str | None = None,
    ) -> bool:
        """Insert or update a host. Returns False if MAC is unusable.

        `vendor` is the manufacturer (or, failing that, the probed device type).
        It arrives later than the rest of the identity because the lookups run
        after the packet is recorded, so a known value is kept until a new
        known one replaces it.
        """
        normalized_mac = self._normalize_mac(mac)
        if normalized_mac is None:
            return False

        seen_at = time.time() if last_seen is None else last_seen
        hostname = hostname or UNKNOWN_VALUE
        ip = ip or UNKNOWN_VALUE
        vendor = vendor.strip() if vendor else None
        if vendor == UNKNOWN_VALUE:
            vendor = None

        with self._condition:
            existing = self._hosts.get(normalized_mac)
            if existing is None:
                self._hosts[normalized_mac] = {
                    "mac": normalized_mac,
                    "hostname": hostname,
                    "ip": ip,
                    "vendor": vendor,
                    "last_seen": seen_at,
                }
            else:
                if hostname != UNKNOWN_VALUE:
                    existing["hostname"] = hostname
                if ip != UNKNOWN_VALUE:
                    existing["ip"] = ip
                if vendor:
                    existing["vendor"] = vendor
                existing["last_seen"] = seen_at
            self._bump_version_locked()
        return True

    def expire_older_than(self, now: float | None = None) -> int:
        """Remove hosts whose last_seen is older than the quiet period. Returns count removed."""
        cutoff = (time.time() if now is None else now) - self._quiet_period_seconds
        with self._condition:
            stale = [mac for mac, host in self._hosts.items() if host["last_seen"] <= cutoff]
            for mac in stale:
                del self._hosts[mac]
            if stale:
                self._bump_version_locked()
            return len(stale)

    def snapshot(self) -> list[dict[str, Any]]:
        """Return a copy of current hosts, newest last_seen first."""
        with self._lock:
            hosts = [dict(host) for host in self._hosts.values()]
        hosts.sort(key=lambda h: h["last_seen"], reverse=True)
        return hosts

    def wait_for_change(self, since_version: int, timeout: float | None = None) -> bool:
        """Block until version advances past since_version. Returns True if changed."""
        with self._condition:
            if self._version > since_version:
                return True
            self._condition.wait(timeout=timeout)
            return self._version > since_version

    def wake_waiters(self) -> None:
        """Wake SSE/wait loops without changing roster contents (e.g. on shutdown)."""
        with self._condition:
            self._condition.notify_all()

    def seed_from_entries(self, entries: list[dict[str, Any]]) -> int:
        """Bulk-load seed entries without treating unknown identity specially beyond upsert."""
        count = 0
        for entry in entries:
            if self.upsert(
                entry.get("mac"),
                entry.get("hostname"),
                entry.get("ip"),
                last_seen=entry.get("last_seen"),
                vendor=entry.get("vendor"),
            ):
                count += 1
        return count

    def _bump_version_locked(self) -> None:
        self._version += 1
        self._condition.notify_all()

    @staticmethod
    def _normalize_mac(mac: str | None) -> str | None:
        if not mac or mac.lower() == UNKNOWN_MAC:
            return None
        return mac.lower()
