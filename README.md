# DHCP Watch

Monitor DHCP Request packets and log device hostname, IP, and MAC address. Optionally send alerts to Telegram. While running, also serves a LAN-only live hosts page.

## Usage

```bash
sudo python3 dhcp_watch.py
```

Then open the live hosts page from another device on the same LAN:

```text
http://<pi-or-host-ip>:8888/
```

The page lists recently detected hosts (MAC-keyed identity + last-seen) and updates live over SSE. Hosts drop off after an hour without DHCP activity. On startup, the roster is seeded from recent entries in `/tmp/dhcp_watch.log` (best-effort; `/tmp` may be cleared on reboot).

### Live page security notes

- The page is **unauthenticated** and binds `0.0.0.0:8888` (all interfaces) by default — intended for a trusted home LAN only. Change `web_bind_host` / `web_port` in `config.json` to narrow this.
- The HTTP server runs **in the same process** as packet capture, which often means root. Prefer granting capabilities to `tcpdump` (below) and limiting `:8888` with a host firewall when possible.

## Configuration

Settings are read from two files, in order:

1. **`config.default.json`** — every non-secret default (capture interface, log
   path, debounce and quiet periods, web bind address and port, lookup hosts and
   timeouts). It is checked into git; the reference below documents every setting
   it holds.
2. **`config.json`** — git-ignored, optional, and layered on top. Only include
   the keys you want to change; anything you leave out keeps its default.

The merge is per key: a key in `config.json` replaces the default outright, so
overriding a list or object means giving the full replacement value. An invalid
`config.json` is reported on stderr and ignored in favour of the defaults.

Telegram credentials (`bot_token`, `chat_id`) live only in `config.json` — they
have no default, and alerts stay off until both are set. Common overrides:

```json
{
  "bot_token": "YOUR_BOT_TOKEN",
  "chat_id": "YOUR_CHAT_ID",
  "interface": "eth0",
  "web_port": 8080,
  "quiet_period_seconds": 1800,
  "ignored_hostnames": ["Watch"],
  "location": "Home"
}
```

### Reference

Every setting, with the default it takes when `config.json` leaves it out. Times
are in seconds throughout.

**Telegram credentials** — secrets, so they have no default and belong only in
`config.json`. Alerts stay off until both are set, and setting just one is an
error.

| Setting | Default | Description |
| --- | --- | --- |
| `bot_token` | — | Bot token from [@BotFather](https://t.me/BotFather). |
| `chat_id` | — | Chat the alerts are sent to. |

**Alerting** — what reaches Telegram. Filtering here never affects the log or the
live hosts page.

| Setting | Default | Description |
| --- | --- | --- |
| `alert_on_message_types` | `["Discover"]` | DHCP message types worth an alert. `Discover` means a device is looking for a lease — usually new or returning. `Request` also covers routine lease renewals, so it is far chattier. |
| `ignored_hostnames` | `[]` | Hostnames that never raise an alert, matched case-insensitively against the whole name. |
| `ignored_macs` | `[]` | MAC addresses that never raise an alert, matched case-insensitively (e.g. `"f0:81:73:61:ec:0c"`). |
| `location` | `null` | Label prefixed to every alert, e.g. `"Home"`. Left unset, the approximate city from `geolocation_lookup_host` is used instead. |

**Capture** — how packets are sniffed and recorded.

| Setting | Default | Description |
| --- | --- | --- |
| `interface` | `"any"` | Interface tcpdump captures on; `any` listens on all of them. Name a specific one (e.g. `"eth0"`) to avoid duplicate packets on a host with several interfaces on the same LAN. |
| `tcpdump_command` | `"tcpdump"` | The tcpdump executable, resolved on `PATH` unless given as an absolute path. |
| `log_file` | `"/tmp/dhcp_watch.log"` | Append-only log of detected packets, also read back on startup to seed the live roster. Note that `/tmp` is often cleared on reboot. |
| `debounce_seconds` | `3600` | Per-MAC quiet window after a packet is handled. Repeats inside it still print to the console, but are not logged and raise no alert, which keeps chatty devices from flooding the chat. |

**Live hosts page** — the LAN-only web UI. See the security notes above before
widening `web_bind_host`.

| Setting | Default | Description |
| --- | --- | --- |
| `web_bind_host` | `"0.0.0.0"` | Address the page binds to. The default accepts connections on every interface; `"127.0.0.1"` restricts it to this host. |
| `web_port` | `8888` | TCP port for the page. Startup fails if it is already taken. |
| `quiet_period_seconds` | `3600` | How long a host stays listed after its last DHCP activity. Shown on the page itself as the drop-off window. |
| `aging_sweep_interval_seconds` | `60` | How often the background sweep drops expired hosts, so entries age out even while the LAN is silent. Lower means a crisper drop-off, at the cost of more wakeups. |
| `sse_heartbeat_seconds` | `15` | Interval between keep-alive events on the page's SSE stream, which stops idle connections being closed by proxies or browsers. |

**Outbound lookups** — the external services used for alerts and device
identification. The base URLs are worth changing mainly for a proxy or a test
double; every lookup here fails soft, degrading what is reported rather than
stopping capture.

| Setting | Default | Description |
| --- | --- | --- |
| `telegram_api_base_url` | `"https://api.telegram.org"` | Base URL of the Telegram Bot API. |
| `telegram_timeout_seconds` | `10` | Timeout for a single Telegram send. A timed-out alert is reported on stderr and dropped, never retried. |
| `mac_vendor_api_base_url` | `"https://api.macvendors.com"` | Base URL of the MAC vendor lookup API, queried once per OUI (the first three octets of a MAC) and then cached in memory. |
| `vendor_lookup_timeout_seconds` | `5` | Timeout for a vendor lookup. On failure the device is reported without a vendor, which is what triggers the nmap probe. |
| `http_user_agent` | `"dhcp-watch/1.0"` | User-Agent sent with vendor lookups. |
| `nmap_port_device_map` | Apple ports (see file) | Open TCP port to device label, e.g. `{"62078": "iPhone/iPad"}`. These ports are the ones nmap scans, and the first match names the device; otherwise the OS fingerprint decides. Only consulted when the vendor lookup came up empty, typically for a device using a randomised MAC. |
| `nmap_timeout_seconds` | `30` | Timeout for the nmap probe. It runs an OS scan, so allow generous time or accept that slower devices go unidentified. |
| `external_ip_lookup_host` | `"ifconfig.me"` | Host `curl` asks for this machine's external IPv4 and IPv6, shown at startup and in the Telegram startup message. |
| `geolocation_lookup_host` | `"ipinfo.io"` | Host queried for approximate city/country/coordinates when `location` is unset. Expected to answer with JSON. |
| `external_lookup_timeout_seconds` | `5` | Timeout shared by the external IP and geolocation lookups. Both run once at startup and are skipped on failure. |

## Grant tcpdump capabilities (Linux)

If you want to run without `sudo`, grant packet-capture capabilities to `tcpdump`:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(which tcpdump)"
```

Then run:

```bash
python3 dhcp_watch.py
```

Verify capabilities:

```bash
getcap "$(which tcpdump)"
```

Remove capabilities (revert):

```bash
sudo setcap -r "$(which tcpdump)"
```

## Telegram Alerts

See [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md) for configuration instructions.
