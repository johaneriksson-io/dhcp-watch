"""Layered configuration: config.default.json first, then config.json on top.

`config.default.json` holds every non-secret default and is checked into git.
`config.json` is git-ignored and only needs the keys a host wants to override
(typically the Telegram credentials).
"""

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import sys

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

DEFAULT_CONFIG_FILE = Path(__file__).parent / "config.default.json"
USER_CONFIG_FILE = Path(__file__).parent / "config.json"


class ConfigModel(BaseModel):
    # Telegram credentials: secrets, so they only ever live in config.json.
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None

    # Alerting
    ignored_hostnames: List[str] = Field(default_factory=list)
    ignored_macs: List[str] = Field(default_factory=list)
    alert_on_message_types: List[str] = Field(default_factory=lambda: ["Discover"])
    location: Optional[str] = None

    # Capture
    log_file: str = "/tmp/dhcp_watch.log"
    interface: str = "any"
    tcpdump_command: str = "tcpdump"
    debounce_seconds: int = 600

    # Live roster / web UI
    quiet_period_seconds: int = 600
    aging_sweep_interval_seconds: float = 5
    web_bind_host: str = "0.0.0.0"
    web_port: int = Field(default=8888, ge=0, le=65535)
    sse_heartbeat_seconds: float = 15

    # Outbound lookups
    http_user_agent: str = "dhcp-watch/1.0"
    telegram_api_base_url: str = "https://api.telegram.org"
    telegram_timeout_seconds: float = 10
    mac_vendor_api_base_url: str = "https://api.macvendors.com"
    vendor_lookup_timeout_seconds: float = 5
    external_ip_lookup_host: str = "ifconfig.me"
    geolocation_lookup_host: str = "ipinfo.io"
    external_lookup_timeout_seconds: float = 5
    nmap_timeout_seconds: float = 30
    nmap_port_device_map: Dict[int, str] = Field(default_factory=dict)

    @property
    def telegram_enabled(self) -> bool:
        """True when both Telegram credentials are configured."""
        return bool(self.bot_token and self.chat_id)

    @field_validator("bot_token", "chat_id")
    @classmethod
    def _reject_blank_credentials(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not value.strip():
            raise ValueError("must not be empty")
        return value

    @model_validator(mode="after")
    def _require_both_credentials(self) -> "ConfigModel":
        if (self.bot_token is None) != (self.chat_id is None):
            raise ValueError("bot_token and chat_id must be set together")
        return self


def _read_json_object(path: Path) -> Optional[Dict[str, Any]]:
    """Return a JSON object from `path`, or None if absent or unusable."""
    if not path.is_file():
        return None
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        print(f"Error reading {path}: expected a JSON object", file=sys.stderr)
        return None
    return data


def load_and_validate_config(
    config_path: Path = USER_CONFIG_FILE,
    defaults_path: Path = DEFAULT_CONFIG_FILE,
) -> ConfigModel:
    """Load the defaults, then overlay the user config on top of them.

    The merge is per key: a key present in `config.json` replaces the default
    value outright (lists and dicts included). Always returns a ConfigModel —
    a missing or invalid layer falls back to the layers that did load, and
    finally to the field defaults declared above.
    """
    defaults = _read_json_object(defaults_path) or {}
    overrides = _read_json_object(config_path) or {}

    layers = []
    if overrides:
        layers.append(({**defaults, **overrides}, config_path))
    layers.append((defaults, defaults_path))

    for data, source in layers:
        try:
            return ConfigModel(**data)
        except ValidationError as e:
            print(f"Error loading configuration from {source}: {e}", file=sys.stderr)

    return ConfigModel()


@lru_cache(maxsize=1)
def load_defaults() -> ConfigModel:
    """The checked-in defaults alone, with no user overrides applied.

    Used for module-level defaults in code that has no config handy; the main
    entry point passes the merged config explicitly instead.
    """
    return ConfigModel(**(_read_json_object(DEFAULT_CONFIG_FILE) or {}))
