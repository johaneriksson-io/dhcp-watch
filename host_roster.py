"""Thread-safe in-memory host roster for the live hosts web UI."""

from __future__ import annotations

import threading
import time
from typing import Any

UNKNOWN_MAC = "unknown"
UNKNOWN_VALUE = "unknown"
QUIET_PERIOD_SECONDS = 600


class HostRoster:
    """MAC-keyed host store with upsert, expire, snapshot, and change wait."""

    def __init__(self, quiet_period_seconds: int = QUIET_PERIOD_SECONDS):
        self._quiet_period_seconds = quiet_period_seconds
        self._hosts: dict[str, dict[str, Any]] = {}
        self._version = 0
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)

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
    ) -> bool:
        """Insert or update a host. Returns False if MAC is unusable."""
        normalized_mac = self._normalize_mac(mac)
        if normalized_mac is None:
            return False

        seen_at = time.time() if last_seen is None else last_seen
        hostname = hostname or UNKNOWN_VALUE
        ip = ip or UNKNOWN_VALUE

        with self._condition:
            existing = self._hosts.get(normalized_mac)
            if existing is None:
                self._hosts[normalized_mac] = {
                    "mac": normalized_mac,
                    "hostname": hostname if hostname != UNKNOWN_VALUE else UNKNOWN_VALUE,
                    "ip": ip if ip != UNKNOWN_VALUE else UNKNOWN_VALUE,
                    "last_seen": seen_at,
                }
            else:
                if hostname != UNKNOWN_VALUE:
                    existing["hostname"] = hostname
                if ip != UNKNOWN_VALUE:
                    existing["ip"] = ip
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

    def seed_from_entries(self, entries: list[dict[str, Any]]) -> int:
        """Bulk-load seed entries without treating unknown identity specially beyond upsert."""
        count = 0
        for entry in entries:
            if self.upsert(
                entry.get("mac"),
                entry.get("hostname"),
                entry.get("ip"),
                last_seen=entry.get("last_seen"),
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
