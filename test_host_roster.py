"""Tests for the thread-safe host roster."""

import threading
import time

from config_validator import load_defaults
from host_roster import UNKNOWN_MAC, HostRoster, QUIET_PERIOD_SECONDS


class TestHostRosterUpsert:
    def test_upsert_appears_in_snapshot(self):
        roster = HostRoster()
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=1000.0)

        hosts = roster.snapshot()
        assert len(hosts) == 1
        assert hosts[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert hosts[0]["hostname"] == "phone"
        assert hosts[0]["ip"] == "192.168.1.10"
        assert hosts[0]["last_seen"] == 1000.0

    def test_upsert_same_mac_updates_last_seen_and_identity(self):
        roster = HostRoster()
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=1000.0)
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone-new", "192.168.1.11", last_seen=1100.0)

        hosts = roster.snapshot()
        assert len(hosts) == 1
        assert hosts[0]["hostname"] == "phone-new"
        assert hosts[0]["ip"] == "192.168.1.11"
        assert hosts[0]["last_seen"] == 1100.0

    def test_upsert_does_not_overwrite_with_unknown_identity(self):
        roster = HostRoster()
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=1000.0)
        roster.upsert("aa:bb:cc:dd:ee:ff", "unknown", "unknown", last_seen=1100.0)

        hosts = roster.snapshot()
        assert hosts[0]["hostname"] == "phone"
        assert hosts[0]["ip"] == "192.168.1.10"
        assert hosts[0]["last_seen"] == 1100.0

    def test_vendor_stored_and_kept_when_a_later_packet_omits_it(self):
        roster = HostRoster()
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=1000.0)
        assert roster.snapshot()[0]["vendor"] is None

        roster.upsert(
            "aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=1000.0,
            vendor="Apple, Inc.",
        )
        assert roster.snapshot()[0]["vendor"] == "Apple, Inc."

        # The next packet is recorded before its vendor lookup answers.
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=1100.0)
        hosts = roster.snapshot()
        assert hosts[0]["vendor"] == "Apple, Inc."
        assert hosts[0]["last_seen"] == 1100.0

    def test_vendor_replaced_when_a_new_one_is_known(self):
        roster = HostRoster()
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "1.1.1.1", last_seen=1000.0, vendor="Old")
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "1.1.1.1", last_seen=1100.0, vendor="New")
        assert roster.snapshot()[0]["vendor"] == "New"

    def test_blank_and_unknown_vendor_do_not_become_a_label(self):
        roster = HostRoster()
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "1.1.1.1", last_seen=1000.0, vendor="unknown")
        assert roster.snapshot()[0]["vendor"] is None
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "1.1.1.1", last_seen=1000.0, vendor="   ")
        assert roster.snapshot()[0]["vendor"] is None

    def test_mac_normalized_to_lowercase(self):
        roster = HostRoster()
        roster.upsert("AA:BB:CC:DD:EE:FF", "phone", "192.168.1.10", last_seen=1000.0)

        hosts = roster.snapshot()
        assert hosts[0]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_unknown_mac_skipped(self):
        roster = HostRoster()
        assert roster.upsert(UNKNOWN_MAC, "phone", "192.168.1.10", last_seen=1000.0) is False
        assert roster.upsert(None, "phone", "192.168.1.10", last_seen=1000.0) is False
        assert roster.upsert("", "phone", "192.168.1.10", last_seen=1000.0) is False
        assert roster.snapshot() == []


class TestHostRosterExpire:
    def test_expire_removes_only_older_entries(self):
        roster = HostRoster(quiet_period_seconds=600)
        roster.upsert("aa:bb:cc:dd:ee:01", "old", "192.168.1.1", last_seen=1000.0)
        roster.upsert("aa:bb:cc:dd:ee:02", "new", "192.168.1.2", last_seen=1500.0)

        removed = roster.expire_older_than(now=1600.0)

        assert removed == 1
        hosts = roster.snapshot()
        assert len(hosts) == 1
        assert hosts[0]["mac"] == "aa:bb:cc:dd:ee:02"

    def test_expire_noop_when_nothing_aged_out(self):
        roster = HostRoster(quiet_period_seconds=600)
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=1500.0)

        removed = roster.expire_older_than(now=1600.0)

        assert removed == 0
        assert len(roster.snapshot()) == 1


class TestHostRosterWaitNotify:
    def test_wait_wakes_on_upsert(self):
        roster = HostRoster()
        woke = []

        def waiter():
            changed = roster.wait_for_change(since_version=0, timeout=2.0)
            woke.append(changed)

        thread = threading.Thread(target=waiter)
        thread.start()
        time.sleep(0.05)
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=1000.0)
        thread.join(timeout=2.0)

        assert woke == [True]
        assert roster.version > 0

    def test_wait_wakes_all_waiters(self):
        roster = HostRoster()
        results = []
        barrier = threading.Barrier(3)

        def waiter():
            barrier.wait(timeout=2.0)
            changed = roster.wait_for_change(since_version=0, timeout=2.0)
            results.append(changed)

        threads = [threading.Thread(target=waiter) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=2.0)
        time.sleep(0.05)
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=1000.0)
        for thread in threads:
            thread.join(timeout=2.0)

        assert results == [True, True]

    def test_wait_wakes_on_expire_that_removes(self):
        roster = HostRoster(quiet_period_seconds=600)
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=1000.0)
        version = roster.version
        woke = []

        def waiter():
            changed = roster.wait_for_change(since_version=version, timeout=2.0)
            woke.append(changed)

        thread = threading.Thread(target=waiter)
        thread.start()
        time.sleep(0.05)
        roster.expire_older_than(now=2000.0)
        thread.join(timeout=2.0)

        assert woke == [True]

    def test_quiet_period_default_comes_from_config(self):
        assert QUIET_PERIOD_SECONDS == load_defaults().quiet_period_seconds
        assert HostRoster().quiet_period_seconds == QUIET_PERIOD_SECONDS
