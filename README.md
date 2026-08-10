# DHCP Watch

Monitor DHCP Request packets and log device hostname, IP, and MAC address. Optionally send alerts to Telegram. While running, also serves a LAN-only live hosts page.

## Usage

```bash
sudo python3 dhcp_watch.py
```

Then open the live hosts page from another device on the same LAN:

```text
http://<pi-or-host-ip>:8080/
```

The page lists recently detected hosts (MAC-keyed identity + last-seen) and updates live over SSE. Hosts drop off after 10 minutes without DHCP activity. On startup, the roster is seeded from recent entries in `/tmp/dhcp_watch.log` (best-effort; `/tmp` may be cleared on reboot).

### Live page security notes

- The page is **unauthenticated** and binds `0.0.0.0:8080` (all interfaces) by default — intended for a trusted home LAN only.
- The HTTP server runs **in the same process** as packet capture, which often means root. Prefer granting capabilities to `tcpdump` (below) and limiting `:8080` with a host firewall when possible.

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
