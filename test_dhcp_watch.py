import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from config_validator import (
    DEFAULT_CONFIG_FILE,
    ConfigModel,
    load_and_validate_config,
    load_defaults,
)
import dhcp_watch
from dhcp_watch import (
    lookup_vendor,
    probe_device_type,
    is_hostname_ignored,
    is_mac_ignored,
    send_telegram_alert,
    send_telegram_message,
    load_config,
    get_external_ip,
    get_geolocation,
    apply_packet_to_roster,
    start_aging_sweep,
    UNKNOWN_VALUE,
)
from host_roster import HostRoster, seed_roster_from_log
from web_ui import start_web_server, stop_web_server
import threading
import time
import urllib.request


# --- config_validator tests ---


class TestConfigModel:
    def test_valid_config(self):
        config = ConfigModel(bot_token="abc123", chat_id="456")
        assert config.bot_token == "abc123"
        assert config.chat_id == "456"
        assert config.ignored_hostnames == []
        assert config.ignored_macs == []
        assert config.location is None

    def test_valid_config_with_lists(self):
        config = ConfigModel(
            bot_token="tok",
            chat_id="cid",
            ignored_hostnames=["host1"],
            ignored_macs=["aa:bb:cc:dd:ee:ff"],
        )
        assert config.ignored_hostnames == ["host1"]
        assert config.ignored_macs == ["aa:bb:cc:dd:ee:ff"]

    def test_valid_config_with_location(self):
        config = ConfigModel(bot_token="tok", chat_id="cid", location="Home, Stockholm")
        assert config.location == "Home, Stockholm"

    def test_missing_bot_token(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ConfigModel(chat_id="456")

    def test_missing_chat_id(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ConfigModel(bot_token="abc")

    def test_empty_bot_token(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ConfigModel(bot_token="", chat_id="456")


class TestConfigDefaultsFile:
    def test_default_file_is_present_and_valid(self):
        assert DEFAULT_CONFIG_FILE.is_file()
        defaults = load_defaults()
        assert defaults.web_port == 8888
        assert defaults.quiet_period_seconds == 3600
        assert defaults.log_file == "/tmp/dhcp_watch.log"
        assert defaults.interface == "any"
        assert defaults.alert_on_message_types == ["Discover"]
        assert defaults.nmap_port_device_map[62078] == "iPhone/iPad"

    def test_defaults_carry_no_credentials(self):
        defaults = load_defaults()
        assert defaults.bot_token is None
        assert defaults.chat_id is None
        assert defaults.telegram_enabled is False


class TestLoadAndValidateConfig:
    def test_missing_user_file_falls_back_to_defaults(self, tmp_path):
        result = load_and_validate_config(tmp_path / "nonexistent.json")
        assert result.web_port == load_defaults().web_port
        assert result.telegram_enabled is False

    def test_valid_file(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"bot_token": "tok", "chat_id": "cid"}))
        result = load_and_validate_config(cfg)
        assert result is not None
        assert result.bot_token == "tok"
        assert result.chat_id == "cid"
        assert result.telegram_enabled is True

    def test_user_file_overrides_defaults(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"web_port": 9999, "interface": "eth0"}))
        result = load_and_validate_config(cfg)
        assert result.web_port == 9999
        assert result.interface == "eth0"
        # Untouched keys still come from the defaults layer.
        assert result.log_file == load_defaults().log_file

    def test_user_file_replaces_list_defaults_wholesale(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"alert_on_message_types": ["Request", "Discover"]}))
        result = load_and_validate_config(cfg)
        assert result.alert_on_message_types == ["Request", "Discover"]

    def test_defaults_layer_is_read_when_user_file_absent(self, tmp_path):
        defaults = tmp_path / "config.default.json"
        defaults.write_text(json.dumps({"web_port": 7070}))
        result = load_and_validate_config(tmp_path / "nope.json", defaults)
        assert result.web_port == 7070

    def test_invalid_json_falls_back_to_defaults(self, tmp_path, capsys):
        cfg = tmp_path / "config.json"
        cfg.write_text("{bad json")
        result = load_and_validate_config(cfg)
        assert result.web_port == load_defaults().web_port
        assert "Error reading" in capsys.readouterr().err

    def test_partial_credentials_fall_back_to_defaults(self, tmp_path, capsys):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"bot_token": "tok"}))
        result = load_and_validate_config(cfg)
        assert result.telegram_enabled is False
        assert "Error loading configuration" in capsys.readouterr().err


# --- is_hostname_ignored tests ---


class TestIsHostnameIgnored:
    def test_match(self):
        assert is_hostname_ignored("MyPhone", ["myphone"]) is True

    def test_case_insensitive(self):
        assert is_hostname_ignored("MYPHONE", ["myphone"]) is True

    def test_no_match(self):
        assert is_hostname_ignored("laptop", ["myphone"]) is False

    def test_unknown_hostname(self):
        assert is_hostname_ignored(UNKNOWN_VALUE, ["myphone"]) is False

    def test_empty_list(self):
        assert is_hostname_ignored("anything", []) is False

    def test_none_list(self):
        assert is_hostname_ignored("anything", None) is False


# --- is_mac_ignored tests ---


class TestIsMacIgnored:
    def test_match(self):
        assert is_mac_ignored("aa:bb:cc:dd:ee:ff", ["AA:BB:CC:DD:EE:FF"]) is True

    def test_case_insensitive(self):
        assert is_mac_ignored("AA:BB:CC:DD:EE:FF", ["aa:bb:cc:dd:ee:ff"]) is True

    def test_no_match(self):
        assert is_mac_ignored("11:22:33:44:55:66", ["aa:bb:cc:dd:ee:ff"]) is False

    def test_unknown_mac(self):
        assert is_mac_ignored(UNKNOWN_VALUE, ["aa:bb:cc:dd:ee:ff"]) is False

    def test_empty_list(self):
        assert is_mac_ignored("aa:bb:cc:dd:ee:ff", []) is False


# --- send_telegram_alert tests ---


class TestSendTelegramAlert:
    def _make_packet(self, **overrides):
        packet = {
            "hostname": "test-device",
            "ip": "192.168.1.100",
            "mac": "aa:bb:cc:dd:ee:ff",
            "timestamp": "12:34:56.789",
            "vendor": None,
            "device_type": None,
        }
        packet.update(overrides)
        return packet

    @patch("dhcp_watch.send_telegram_message")
    def test_basic_alert(self, mock_send):
        config = ConfigModel(bot_token="tok", chat_id="cid")
        packet = self._make_packet()
        send_telegram_alert(config, packet)
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][1]
        assert "Hostname: test-device" in msg
        assert "IP: 192.168.1.100" in msg
        assert "MAC: aa:bb:cc:dd:ee:ff" in msg

    @patch("dhcp_watch.send_telegram_message")
    def test_alert_with_location(self, mock_send):
        config = ConfigModel(bot_token="tok", chat_id="cid")
        packet = self._make_packet()
        send_telegram_alert(config, packet, location="Stockholm, SE")
        msg = mock_send.call_args[0][1]
        assert msg.startswith("Stockholm, SE")

    @patch("dhcp_watch.send_telegram_message")
    def test_alert_with_vendor(self, mock_send):
        config = ConfigModel(bot_token="tok", chat_id="cid")
        packet = self._make_packet(vendor="Apple, Inc.")
        send_telegram_alert(config, packet)
        msg = mock_send.call_args[0][1]
        assert "Vendor: Apple, Inc." in msg
        assert "MAC: aa:bb:cc:dd:ee:ff (Apple, Inc.)" in msg

    @patch("dhcp_watch.send_telegram_message")
    def test_alert_with_device_type(self, mock_send):
        config = ConfigModel(bot_token="tok", chat_id="cid")
        packet = self._make_packet(device_type="Linux")
        send_telegram_alert(config, packet)
        msg = mock_send.call_args[0][1]
        assert "Device: Linux" in msg
        assert "MAC: aa:bb:cc:dd:ee:ff (Linux)" in msg

    @patch("dhcp_watch.send_telegram_message")
    def test_unknown_hostname_omitted(self, mock_send):
        config = ConfigModel(bot_token="tok", chat_id="cid")
        packet = self._make_packet(hostname=UNKNOWN_VALUE)
        send_telegram_alert(config, packet)
        msg = mock_send.call_args[0][1]
        assert "Hostname:" not in msg

    @patch("dhcp_watch.send_telegram_message")
    def test_unknown_ip_omitted(self, mock_send):
        config = ConfigModel(bot_token="tok", chat_id="cid")
        packet = self._make_packet(ip=UNKNOWN_VALUE)
        send_telegram_alert(config, packet)
        msg = mock_send.call_args[0][1]
        assert "IP:" not in msg

    @patch("dhcp_watch.send_telegram_message")
    def test_unknown_mac_omitted(self, mock_send):
        config = ConfigModel(bot_token="tok", chat_id="cid")
        packet = self._make_packet(mac=UNKNOWN_VALUE)
        send_telegram_alert(config, packet)
        msg = mock_send.call_args[0][1]
        assert "MAC:" not in msg


# --- send_telegram_message tests ---


class TestSendTelegramMessage:
    @patch("dhcp_watch.urllib.request.urlopen")
    def test_sends_request(self, mock_urlopen):
        config = ConfigModel(bot_token="tok", chat_id="cid")
        send_telegram_message(config, "hello")
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert "bot" + "tok" in req.full_url
        assert b"chat_id=cid" in req.data
        assert b"text=hello" in req.data

    @patch("dhcp_watch.urllib.request.urlopen", side_effect=Exception("network error"))
    def test_handles_error_gracefully(self, mock_urlopen, capsys):
        config = ConfigModel(bot_token="tok", chat_id="cid")
        send_telegram_message(config, "hello")
        captured = capsys.readouterr()
        assert "Failed to send Telegram message" in captured.err


# --- get_external_ip tests ---


class TestGetExternalIp:
    @patch("dhcp_watch.subprocess.run")
    def test_returns_ip(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="1.2.3.4\n")
        assert get_external_ip() == "1.2.3.4"

    @patch("dhcp_watch.subprocess.run")
    def test_ipv4_uses_dash4_flag(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="1.2.3.4")
        get_external_ip(ipv6=False)
        cmd = mock_run.call_args[0][0]
        assert "-4" in cmd

    @patch("dhcp_watch.subprocess.run")
    def test_ipv6_omits_dash4_flag(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="::1")
        get_external_ip(ipv6=True)
        cmd = mock_run.call_args[0][0]
        assert "-4" not in cmd

    @patch("dhcp_watch.subprocess.run", side_effect=FileNotFoundError)
    def test_returns_none_on_missing_curl(self, mock_run):
        assert get_external_ip() is None

    @patch("dhcp_watch.subprocess.run")
    def test_returns_none_on_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert get_external_ip() is None


# --- get_geolocation tests ---


class TestGetGeolocation:
    @patch("dhcp_watch.subprocess.run")
    def test_returns_parsed_json(self, mock_run):
        geo_data = {"city": "Stockholm", "country": "SE", "loc": "59.33,18.07"}
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(geo_data))
        result = get_geolocation()
        assert result["city"] == "Stockholm"

    @patch("dhcp_watch.subprocess.run")
    def test_returns_none_on_bad_json(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="not json")
        assert get_geolocation() is None

    @patch("dhcp_watch.subprocess.run", side_effect=FileNotFoundError)
    def test_returns_none_on_missing_curl(self, mock_run):
        assert get_geolocation() is None


# --- load_config tests ---


class TestLoadConfig:
    @patch("dhcp_watch.load_and_validate_config")
    def test_delegates_to_validator(self, mock_validate):
        mock_validate.return_value = ConfigModel(bot_token="t", chat_id="c")
        result = load_config()
        assert result.bot_token == "t"
        mock_validate.assert_called_once()

    def test_returns_defaults_without_credentials(self):
        config = load_config()
        assert config.web_port == load_defaults().web_port
        assert config.log_file == load_defaults().log_file


# --- configuration drives runtime behaviour ---


class TestConfigDrivenLookups:
    def test_external_ip_uses_configured_host_and_timeout(self):
        config = ConfigModel(external_ip_lookup_host="example.test", external_lookup_timeout_seconds=7)
        with patch("dhcp_watch.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="1.2.3.4")
            get_external_ip(config=config)
        cmd = mock_run.call_args[0][0]
        assert "example.test" in cmd
        assert cmd[cmd.index("-m") + 1] == "7"
        assert mock_run.call_args[1]["timeout"] == 7 + dhcp_watch.SUBPROCESS_TIMEOUT_MARGIN_SECONDS

    def test_geolocation_uses_configured_host(self):
        config = ConfigModel(geolocation_lookup_host="geo.test")
        with patch("dhcp_watch.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout='{"city": "Ankeborg"}')
            assert get_geolocation(config=config)["city"] == "Ankeborg"
        assert "geo.test" in mock_run.call_args[0][0]

    def test_vendor_lookup_uses_configured_api_and_user_agent(self):
        config = ConfigModel(
            mac_vendor_api_base_url="https://vendors.test",
            http_user_agent="dhcp-watch/test",
            vendor_lookup_timeout_seconds=3,
        )
        dhcp_watch._vendor_cache.clear()
        with patch("dhcp_watch.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = b"Acme"
            assert lookup_vendor("aa:bb:cc:dd:ee:ff", config) == "Acme"
        request = mock_urlopen.call_args[0][0]
        assert request.full_url.startswith("https://vendors.test/")
        assert request.get_header("User-agent") == "dhcp-watch/test"
        assert mock_urlopen.call_args[1]["timeout"] == 3
        dhcp_watch._vendor_cache.clear()

    def test_telegram_uses_configured_api_base_url(self):
        config = ConfigModel(
            bot_token="tok", chat_id="cid", telegram_api_base_url="https://tg.test"
        )
        with patch("dhcp_watch.urllib.request.urlopen") as mock_urlopen:
            send_telegram_message(config, "hi")
        assert mock_urlopen.call_args[0][0].full_url == "https://tg.test/bottok/sendMessage"

    def test_device_probe_scans_configured_ports(self):
        config = ConfigModel(nmap_port_device_map={4711: "Doohickey"}, nmap_timeout_seconds=12)
        dhcp_watch._device_type_cache.clear()
        with patch("dhcp_watch.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="4711/tcp open")
            assert probe_device_type("192.168.1.5", config) == "Doohickey"
        cmd = mock_run.call_args[0][0]
        assert cmd[cmd.index("-p") + 1] == "4711"
        assert mock_run.call_args[1]["timeout"] == 12
        dhcp_watch._device_type_cache.clear()


# --- live roster wiring ---


class TestApplyPacketToRoster:
    def _packet(self, **overrides):
        packet = {
            "hostname": "phone",
            "ip": "192.168.1.10",
            "mac": "aa:bb:cc:dd:ee:ff",
            "timestamp": "12:34:56.789",
            "msg_type": "Request",
        }
        packet.update(overrides)
        return packet

    def test_debounced_style_repeat_still_updates_last_seen(self):
        roster = HostRoster()
        apply_packet_to_roster(roster, self._packet(), last_seen=1000.0)
        apply_packet_to_roster(roster, self._packet(), last_seen=1050.0)
        hosts = roster.snapshot()
        assert len(hosts) == 1
        assert hosts[0]["last_seen"] == 1050.0

    def test_vendor_reaches_the_roster(self):
        roster = HostRoster()
        packet = self._packet(vendor="Apple, Inc.")
        apply_packet_to_roster(roster, packet, last_seen=1000.0)
        assert roster.snapshot()[0]["vendor"] == "Apple, Inc."

    def test_probed_device_type_stands_in_for_a_missing_vendor(self):
        roster = HostRoster()
        packet = self._packet(vendor=None, device_type="iPhone/iPad")
        apply_packet_to_roster(roster, packet, last_seen=1000.0)
        assert roster.snapshot()[0]["vendor"] == "iPhone/iPad"

    def test_upsert_happens_without_vendor_lookup(self):
        roster = HostRoster()
        with patch("dhcp_watch.lookup_vendor") as mock_vendor:
            apply_packet_to_roster(roster, self._packet(), last_seen=1000.0)
            mock_vendor.assert_not_called()
        assert roster.snapshot()[0]["hostname"] == "phone"


class TestAgingSweep:
    def test_idle_sweep_removes_stale_host(self):
        roster = HostRoster(quiet_period_seconds=1)
        roster.upsert("aa:bb:cc:dd:ee:ff", "old", "192.168.1.1", last_seen=time.time() - 5)
        stop = threading.Event()
        start_aging_sweep(roster, stop, interval_seconds=0.05)
        deadline = time.time() + 2
        while time.time() < deadline and roster.snapshot():
            time.sleep(0.05)
        stop.set()
        assert roster.snapshot() == []


class TestSeedThenServe:
    def test_seeded_roster_visible_on_page_startup(self, tmp_path):
        from datetime import datetime, timedelta

        when = datetime.now() - timedelta(seconds=120)
        line = (
            f"{when.strftime('%Y-%m-%d %H:%M:%S')} | Request  | "
            f"Host: laptop | IP: 192.168.1.20 | MAC: aa:bb:cc:dd:ee:01"
        )
        log = tmp_path / "dhcp_watch.log"
        log.write_text(line + "\n")

        roster = HostRoster()
        seeded = seed_roster_from_log(roster, log)
        assert seeded == 1

        httpd, _thread, stop_event = start_web_server(roster, host="127.0.0.1", port=0)
        try:
            host, port = httpd.server_address[:2]
            with urllib.request.urlopen(f"http://{host}:{port}/", timeout=2) as response:
                assert response.status == 200
            assert any(h["hostname"] == "laptop" for h in roster.snapshot())
        finally:
            stop_web_server(httpd, stop_event)
