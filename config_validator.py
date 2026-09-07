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
    bot_token: Optional[str] = Field(
        default=None,
        description="Telegram bot token from @BotFather. Alerts stay off until "
        "this and chat_id are both set.",
    )
    chat_id: Optional[str] = Field(
        default=None,
        description="Telegram chat the alerts are sent to. Must be set together "
        "with bot_token.",
    )

    # Alerting
    ignored_hostnames: List[str] = Field(
        default_factory=list,
        description="Hostnames that never raise a Telegram alert, matched "
        "case-insensitively against the whole name. Logging is unaffected.",
    )
    ignored_macs: List[str] = Field(
        default_factory=list,
        description="MAC addresses that never raise a Telegram alert, matched "
        "case-insensitively (e.g. 'f0:81:73:61:ec:0c'). Logging is unaffected.",
    )
    alert_on_message_types: List[str] = Field(
        default_factory=lambda: ["Discover"],
        description="DHCP message types worth an alert: 'Discover' (a device "
        "looking for a lease, i.e. usually new or returning) and/or 'Request' "
        "(includes routine lease renewals, so it is far chattier).",
    )
    location: Optional[str] = Field(
        default=None,
        description="Label prefixed to every alert, e.g. 'Home'. When unset, the "
        "approximate city from geolocation_lookup_host is used instead.",
    )

    # Capture
    log_file: str = Field(
        default="/tmp/dhcp_watch.log",
        description="Append-only log of detected packets, also read back on "
        "startup to seed the live roster. Note that /tmp is often cleared on "
        "reboot.",
    )
    interface: str = Field(
        default="any",
        description="Interface tcpdump captures on; 'any' listens on all of them. "
        "Set a specific one (e.g. 'eth0') to avoid duplicate packets on a host "
        "with several interfaces on the same LAN.",
    )
    tcpdump_command: str = Field(
        default="tcpdump",
        description="tcpdump executable, resolved on PATH unless given as an "
        "absolute path.",
    )
    debounce_seconds: int = Field(
        default=3600,
        description="Per-MAC quiet window after a packet is handled. Repeats "
        "inside it still print to the console, but are not logged and raise no "
        "alert, which keeps chatty devices from flooding the chat.",
    )

    # Live roster / web UI
    quiet_period_seconds: int = Field(
        default=3600,
        description="How long a host stays on the live hosts page after its last "
        "DHCP activity. Also shown on the page itself as the drop-off window.",
    )
    aging_sweep_interval_seconds: float = Field(
        default=60,
        description="How often the background sweep drops expired hosts, so the "
        "page ages entries out even while the LAN is silent. Lower means a "
        "crisper drop-off, at the cost of more wakeups.",
    )
    web_bind_host: str = Field(
        default="0.0.0.0",
        description="Address the live hosts page binds to. The default accepts "
        "connections on every interface; '127.0.0.1' restricts it to this host. "
        "The page is unauthenticated, so keep it on a trusted LAN.",
    )
    web_port: int = Field(
        default=8888,
        ge=0,
        le=65535,
        description="TCP port for the live hosts page. Startup fails if it is "
        "already taken.",
    )
    sse_heartbeat_seconds: float = Field(
        default=15,
        description="Interval between keep-alive events on the page's SSE stream, "
        "which stops idle connections being closed by proxies or browsers.",
    )

    # Outbound lookups
    http_user_agent: str = Field(
        default="dhcp-watch/1.0",
        description="User-Agent sent with MAC vendor lookups.",
    )
    telegram_api_base_url: str = Field(
        default="https://api.telegram.org",
        description="Base URL of the Telegram Bot API. Worth changing only for a "
        "proxy or a test double.",
    )
    telegram_timeout_seconds: float = Field(
        default=10,
        description="Timeout for a single Telegram send. A timed-out alert is "
        "reported on stderr and dropped, never retried.",
    )
    mac_vendor_api_base_url: str = Field(
        default="https://api.macvendors.com",
        description="Base URL of the MAC vendor lookup API, queried once per OUI "
        "(the first three octets of a MAC) and then cached in memory.",
    )
    vendor_lookup_timeout_seconds: float = Field(
        default=5,
        description="Timeout for a vendor lookup. On failure the device is "
        "reported without a vendor, which then triggers the nmap probe.",
    )
    external_ip_lookup_host: str = Field(
        default="ifconfig.me",
        description="Host curl asks for this machine's external IPv4 and IPv6, "
        "shown at startup and in the Telegram startup message.",
    )
    geolocation_lookup_host: str = Field(
        default="ipinfo.io",
        description="Host queried for approximate city/country/coordinates when "
        "location is unset. Expected to answer with JSON.",
    )
    external_lookup_timeout_seconds: float = Field(
        default=5,
        description="Timeout shared by the external IP and geolocation lookups. "
        "Both run once at startup and are skipped on failure.",
    )
    nmap_timeout_seconds: float = Field(
        default=30,
        description="Timeout for the nmap probe. It runs an OS scan, so allow "
        "generous time or accept that slower devices go unidentified.",
    )
    nmap_port_device_map: Dict[int, str] = Field(
        default_factory=dict,
        description="Open TCP port to device label, e.g. {\"62078\": "
        "\"iPhone/iPad\"}. These ports are the ones nmap scans, and the first "
        "match names the device; otherwise the OS fingerprint decides. Only "
        "consulted when the vendor lookup came up empty, typically for a device "
        "using a randomised MAC.",
    )

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
