import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from config_validator import ConfigModel, load_and_validate_config
from dhcp_watch import (
    is_hostname_ignored,
    is_mac_ignored,
    send_telegram_alert,
    send_telegram_message,
    load_config,
    get_external_ip,
    get_geolocation,
    UNKNOWN_VALUE,
)


# --- config_validator tests ---


class TestConfigModel:
    def test_valid_config(self):
        config = ConfigModel(bot_token="abc123", chat_id="456")
        assert config.bot_token == "abc123"
        assert config.chat_id == "456"
        assert config.ignored_hostnames == []
        assert config.ignored_macs == []

    def test_valid_config_with_lists(self):
        config = ConfigModel(
            bot_token="tok",
            chat_id="cid",
            ignored_hostnames=["host1"],
            ignored_macs=["aa:bb:cc:dd:ee:ff"],
        )
        assert config.ignored_hostnames == ["host1"]
        assert config.ignored_macs == ["aa:bb:cc:dd:ee:ff"]

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


class TestLoadAndValidateConfig:
    def test_missing_file(self, tmp_path):
        result = load_and_validate_config(tmp_path / "nonexistent.json")
        assert result is None

    def test_valid_file(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"bot_token": "tok", "chat_id": "cid"}))
        result = load_and_validate_config(cfg)
        assert result is not None
        assert result.bot_token == "tok"
        assert result.chat_id == "cid"

    def test_invalid_json(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text("{bad json")
        result = load_and_validate_config(cfg)
        assert result is None

    def test_missing_required_fields(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"bot_token": "tok"}))
        result = load_and_validate_config(cfg)
        assert result is None


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

    @patch("dhcp_watch.load_and_validate_config", return_value=None)
    def test_returns_none_when_no_config(self, mock_validate):
        assert load_config() is None
