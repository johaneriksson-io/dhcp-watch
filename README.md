# DHCP Watch

Monitor DHCP Request packets and log device hostname, IP, and MAC address. Optionally send alerts to Telegram.

## Usage

```bash
sudo python3 dhcp_watch.py
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
