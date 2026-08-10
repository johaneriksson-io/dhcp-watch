"""Tests for seeding the host roster from dhcp_watch log lines."""

from datetime import datetime, timedelta
from pathlib import Path

from host_roster import HostRoster, parse_log_line, seed_roster_from_log


def _ts(offset_seconds: float = 0.0) -> datetime:
    return datetime.now() - timedelta(seconds=offset_seconds)


def _line(
    when: datetime,
    mac: str = "aa:bb:cc:dd:ee:ff",
    hostname: str | None = "phone",
    ip: str | None = "192.168.1.10",
    msg_type: str = "Request",
    vendor: str | None = None,
) -> str:
    fields = [when.strftime("%Y-%m-%d %H:%M:%S"), f"{msg_type:8}"]
    if hostname is not None:
        fields.append(f"Host: {hostname}")
    if ip is not None:
        fields.append(f"IP: {ip}")
    mac_str = mac
    if vendor:
        mac_str += f" ({vendor})"
    fields.append(f"MAC: {mac_str}")
    return " | ".join(fields)


class TestParseLogLine:
    def test_parses_full_line(self):
        when = _ts(60)
        entry = parse_log_line(_line(when))
        assert entry is not None
        assert entry["mac"] == "aa:bb:cc:dd:ee:ff"
        assert entry["hostname"] == "phone"
        assert entry["ip"] == "192.168.1.10"
        assert abs(entry["last_seen"] - when.timestamp()) < 1.0

    def test_strips_vendor_suffix_from_mac(self):
        entry = parse_log_line(_line(_ts(60), vendor="Apple Inc."))
        assert entry is not None
        assert entry["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_missing_host_and_ip_still_parses(self):
        entry = parse_log_line(_line(_ts(60), hostname=None, ip=None))
        assert entry is not None
        assert entry["mac"] == "aa:bb:cc:dd:ee:ff"
        assert entry["hostname"] == "unknown"
        assert entry["ip"] == "unknown"

    def test_malformed_line_returns_none(self):
        assert parse_log_line("not a log line") is None
        assert parse_log_line("") is None


class TestSeedRosterFromLog:
    def test_recent_line_seeds_host(self, tmp_path: Path):
        log = tmp_path / "dhcp_watch.log"
        log.write_text(_line(_ts(180)) + "\n")
        roster = HostRoster()

        count = seed_roster_from_log(roster, log)

        assert count == 1
        hosts = roster.snapshot()
        assert hosts[0]["hostname"] == "phone"

    def test_older_than_quiet_excluded(self, tmp_path: Path):
        log = tmp_path / "dhcp_watch.log"
        log.write_text(_line(_ts(900)) + "\n")
        roster = HostRoster(quiet_period_seconds=600)

        count = seed_roster_from_log(roster, log)

        assert count == 0
        assert roster.snapshot() == []

    def test_malformed_skipped_neighbors_seeded(self, tmp_path: Path):
        log = tmp_path / "dhcp_watch.log"
        log.write_text(
            "\n".join(
                [
                    "garbage",
                    _line(_ts(120), mac="aa:bb:cc:dd:ee:01", hostname="a"),
                    "also bad",
                    _line(_ts(90), mac="aa:bb:cc:dd:ee:02", hostname="b"),
                ]
            )
            + "\n"
        )
        roster = HostRoster()

        count = seed_roster_from_log(roster, log)

        assert count == 2
        macs = {h["mac"] for h in roster.snapshot()}
        assert macs == {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}

    def test_duplicate_mac_keeps_latest_timestamp(self, tmp_path: Path):
        older = _line(_ts(300), hostname="old-name")
        newer = _line(_ts(60), hostname="new-name", ip="192.168.1.99")
        # Write newer first so file order ≠ timestamp order
        log = tmp_path / "dhcp_watch.log"
        log.write_text(newer + "\n" + older + "\n")
        roster = HostRoster()

        seed_roster_from_log(roster, log)

        hosts = roster.snapshot()
        assert len(hosts) == 1
        assert hosts[0]["hostname"] == "new-name"
        assert hosts[0]["ip"] == "192.168.1.99"

    def test_missing_log_file_is_empty_seed(self, tmp_path: Path):
        roster = HostRoster()
        count = seed_roster_from_log(roster, tmp_path / "missing.log")
        assert count == 0
        assert roster.snapshot() == []

    def test_ae3_host_seen_minutes_before_restart(self, tmp_path: Path):
        log = tmp_path / "dhcp_watch.log"
        log.write_text(_line(_ts(180), hostname="laptop") + "\n")
        roster = HostRoster()

        seed_roster_from_log(roster, log)

        assert any(h["hostname"] == "laptop" for h in roster.snapshot())
