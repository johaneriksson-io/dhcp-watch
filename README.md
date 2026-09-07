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

The page lists recently detected hosts (MAC-keyed identity + last-seen) and updates live over SSE. Hosts drop off after 10 minutes without DHCP activity. On startup, the roster is seeded from recent entries in `/tmp/dhcp_watch.log` (best-effort; `/tmp` may be cleared on reboot).

### Live page security notes

- The page is **unauthenticated** and binds `0.0.0.0:8888` (all interfaces) by default — intended for a trusted home LAN only. Change `web_bind_host` / `web_port` in `config.json` to narrow this.
- The HTTP server runs **in the same process** as packet capture, which often means root. Prefer granting capabilities to `tcpdump` (below) and limiting `:8888` with a host firewall when possible.

## Configuration

Settings are read from two files, in order:

1. **`config.default.json`** — every non-secret default (capture interface, log
   path, debounce and quiet periods, web bind address and port, lookup hosts and
   timeouts). It is checked into git; treat it as the documented list of
   available settings.
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
