"""LAN web UI and SSE stream for the live host roster."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from host_roster import HostRoster

DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_PORT = 8888
SSE_HEARTBEAT_SECONDS = 15

# Client disconnects while reading headers (common with EventSource reconnect /
# aborted navigations) surface here before do_GET runs.
_BENIGN_DISCONNECT_ERRORS = (
    BrokenPipeError,
    ConnectionResetError,
    ConnectionAbortedError,
    TimeoutError,
)

_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DHCP Watch — Live hosts</title>
  <style>
    :root {
      --bg: #f6f3ee;
      --ink: #1c1a16;
      --muted: #6b645a;
      --line: #d9d2c6;
      --live: #2f6b3a;
      --stale: #8a5a18;
      --err: #8a2f2f;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      background: radial-gradient(circle at top left, #fffaf2, var(--bg));
      color: var(--ink);
      min-height: 100vh;
    }
    main {
      max-width: 42rem;
      margin: 0 auto;
      padding: 1.25rem 1rem 2rem;
    }
    h1 {
      font-size: 1.5rem;
      margin: 0 0 0.35rem;
      letter-spacing: -0.02em;
    }
    #status {
      color: var(--muted);
      font-size: 0.95rem;
      margin-bottom: 1rem;
    }
    #status.live { color: var(--live); }
    #status.reconnecting, #status.stale { color: var(--stale); }
    #status.error { color: var(--err); }
    #hosts {
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: 0.75rem;
    }
    #hosts li {
      border-top: 1px solid var(--line);
      padding: 0.85rem 0 0.15rem;
    }
    .identity {
      font-size: 1.05rem;
      font-weight: 600;
      word-break: break-word;
    }
    .meta {
      color: var(--muted);
      font-size: 0.9rem;
      margin-top: 0.2rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.35rem 0.85rem;
    }
    #empty, #loading {
      color: var(--muted);
      padding: 1rem 0;
    }
    .hidden { display: none; }
  </style>
</head>
<body>
  <main>
    <h1>Live hosts</h1>
    <div id="status">Connecting…</div>
    <div id="loading">Loading roster…</div>
    <div id="empty" class="hidden">No hosts seen in the last 1 hour.</div>
    <ul id="hosts" class="hidden"></ul>
  </main>
  <script>
    const statusEl = document.getElementById("status");
    const loadingEl = document.getElementById("loading");
    const emptyEl = document.getElementById("empty");
    const hostsEl = document.getElementById("hosts");
    let sawSnapshot = false;
    let lastHosts = null;

    function setStatus(text, cls) {
      statusEl.textContent = text;
      statusEl.className = cls || "";
    }

    function formatRelative(epochSeconds) {
      const delta = Math.max(0, Math.floor(Date.now() / 1000 - epochSeconds));
      if (delta < 5) return "just now";
      if (delta < 60) return delta + "s ago";
      if (delta < 3600) return Math.floor(delta / 60) + "m ago";
      return Math.floor(delta / 3600) + "h ago";
    }

    function identityLabel(host) {
      const parts = [];
      if (host.hostname && host.hostname !== "unknown") parts.push(host.hostname);
      if (host.ip && host.ip !== "unknown") parts.push(host.ip);
      if (host.mac) parts.push(host.mac);
      return parts.join(" · ") || host.mac || "unknown host";
    }

    function renderHosts(hosts) {
      lastHosts = hosts;
      sawSnapshot = true;
      loadingEl.classList.add("hidden");
      hostsEl.textContent = "";
      if (!hosts || hosts.length === 0) {
        emptyEl.classList.remove("hidden");
        hostsEl.classList.add("hidden");
        return;
      }
      emptyEl.classList.add("hidden");
      hostsEl.classList.remove("hidden");
      for (const host of hosts) {
        const li = document.createElement("li");
        const identity = document.createElement("div");
        identity.className = "identity";
        identity.textContent = identityLabel(host);
        const meta = document.createElement("div");
        meta.className = "meta";
        const seen = document.createElement("span");
        seen.textContent = formatRelative(host.last_seen);
        seen.title = new Date(host.last_seen * 1000).toLocaleString();
        const mac = document.createElement("span");
        mac.textContent = host.mac || "";
        meta.appendChild(seen);
        if (host.hostname && host.hostname !== "unknown" && host.mac) {
          meta.appendChild(mac);
        }
        li.appendChild(identity);
        li.appendChild(meta);
        hostsEl.appendChild(li);
      }
    }

    function connect() {
      setStatus(sawSnapshot ? "Reconnecting…" : "Connecting…", sawSnapshot ? "reconnecting" : "");
      const source = new EventSource("/events");
      source.onopen = () => {
        setStatus("Live", "live");
      };
      source.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          renderHosts(payload.hosts || []);
          setStatus("Live", "live");
        } catch (err) {
          setStatus("Update error", "error");
        }
      };
      source.onerror = () => {
        source.close();
        setStatus(sawSnapshot ? "Reconnecting…" : "Connecting…", "reconnecting");
        setTimeout(connect, 1500);
      };
    }

    connect();
    setInterval(() => {
      if (lastHosts !== null && sawSnapshot) {
        renderHosts(lastHosts);
      }
    }, 1000);
  </script>
</body>
</html>
"""


class HostsHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server that holds the shared roster and stop event."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, roster: HostRoster, stop_event: threading.Event):
        self.roster = roster
        self.stop_event = stop_event
        super().__init__(server_address, HostsRequestHandler)

    def handle_error(self, request, client_address) -> None:
        """Suppress noisy tracebacks for client disconnects mid-request."""
        exc = sys.exc_info()[1]
        if isinstance(exc, _BENIGN_DISCONNECT_ERRORS):
            return
        super().handle_error(request, client_address)


class HostsRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def roster(self) -> HostRoster:
        return self.server.roster  # type: ignore[attr-defined]

    @property
    def stop_event(self) -> threading.Event:
        return self.server.stop_event  # type: ignore[attr-defined]

    def log_message(self, format: str, *args) -> None:
        # Keep capture console clean; web access is operational noise.
        return

    def handle(self) -> None:
        try:
            super().handle()
        except _BENIGN_DISCONNECT_ERRORS:
            return

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._serve_page()
        elif path == "/events":
            self._serve_sse()
        else:
            self.send_error(404, "Not Found")

    def _serve_page(self) -> None:
        body = _PAGE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _serve_sse(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        version = -1
        try:
            while not self.stop_event.is_set():
                if version < 0 or self.roster.wait_for_change(version, timeout=SSE_HEARTBEAT_SECONDS):
                    version = self.roster.version
                    payload = {
                        "version": version,
                        "hosts": self.roster.snapshot(),
                    }
                    data = json.dumps(payload, separators=(",", ":"))
                    self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
                    self.wfile.flush()
                else:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except _BENIGN_DISCONNECT_ERRORS + (OSError,):
            return


def start_web_server(
    roster: HostRoster,
    *,
    host: str = DEFAULT_BIND_HOST,
    port: int = DEFAULT_PORT,
    stop_event: threading.Event | None = None,
) -> tuple[HostsHTTPServer, threading.Thread, threading.Event]:
    """Bind and start the HTTP server in a daemon thread.

    Raises OSError on bind failure.
    """
    event = stop_event or threading.Event()
    httpd = HostsHTTPServer((host, port), roster, event)
    thread = threading.Thread(target=httpd.serve_forever, name="dhcp-watch-web", daemon=True)
    thread.start()
    return httpd, thread, event


def stop_web_server(httpd: HostsHTTPServer, stop_event: threading.Event) -> None:
    """Signal SSE loops to stop and shut down the server."""
    stop_event.set()
    httpd.roster.wake_waiters()
    httpd.shutdown()
    httpd.server_close()
