"""Tests for the live hosts HTTP page and SSE stream."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.client import HTTPConnection

import pytest

from host_roster import HostRoster
from web_ui import start_web_server, stop_web_server


@pytest.fixture
def live_server():
    roster = HostRoster(quiet_period_seconds=600)
    roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=time.time())
    httpd, _thread, stop_event = start_web_server(roster, host="127.0.0.1", port=0)
    host, port = httpd.server_address[:2]
    yield roster, f"http://{host}:{port}", httpd, stop_event
    stop_web_server(httpd, stop_event)


def _read_sse_events(url: str, count: int, timeout: float = 3.0) -> list[dict]:
    events: list[dict] = []
    deadline = time.time() + timeout
    conn = HTTPConnection("127.0.0.1", int(url.rsplit(":", 1)[1]), timeout=timeout)
    try:
        conn.request("GET", "/events")
        response = conn.getresponse()
        assert response.status == 200
        buffer = ""
        while len(events) < count and time.time() < deadline:
            chunk = response.read(1)
            if not chunk:
                break
            buffer += chunk.decode("utf-8", errors="replace")
            while "\n\n" in buffer:
                frame, buffer = buffer.split("\n\n", 1)
                for line in frame.splitlines():
                    if line.startswith("data: "):
                        events.append(json.loads(line[6:]))
                        break
                if len(events) >= count:
                    break
    finally:
        conn.close()
    return events


class TestWebPage:
    def test_index_returns_html_with_event_source(self, live_server):
        _roster, base_url, _httpd, _stop = live_server
        with urllib.request.urlopen(base_url + "/", timeout=2) as response:
            body = response.read().decode()
        assert response.status == 200
        assert "text/html" in response.headers.get("Content-Type", "")
        assert "EventSource" in body
        assert "/events" in body
        assert "No hosts seen in the last 1 hour." in body
        assert "textContent" in body


class TestSSE:
    def test_first_event_is_full_snapshot(self, live_server):
        roster, base_url, _httpd, _stop = live_server
        events = _read_sse_events(base_url, count=1)
        assert len(events) == 1
        assert "hosts" in events[0]
        assert events[0]["hosts"][0]["hostname"] == "phone"
        assert events[0]["version"] == roster.version

    def test_upsert_pushes_updated_snapshot(self, live_server):
        roster, base_url, _httpd, _stop = live_server
        ready = threading.Event()
        events: list[dict] = []

        def reader():
            conn = HTTPConnection("127.0.0.1", int(base_url.rsplit(":", 1)[1]), timeout=5)
            try:
                conn.request("GET", "/events")
                response = conn.getresponse()
                buffer = ""
                while len(events) < 2:
                    chunk = response.read(1)
                    if not chunk:
                        break
                    buffer += chunk.decode("utf-8", errors="replace")
                    while "\n\n" in buffer:
                        frame, buffer = buffer.split("\n\n", 1)
                        for line in frame.splitlines():
                            if line.startswith("data: "):
                                events.append(json.loads(line[6:]))
                                if len(events) == 1:
                                    ready.set()
                                break
                        if len(events) >= 2:
                            return
            finally:
                conn.close()

        thread = threading.Thread(target=reader)
        thread.start()
        assert ready.wait(timeout=3)
        roster.upsert("aa:bb:cc:dd:ee:ff", "phone", "192.168.1.10", last_seen=time.time() + 1)
        thread.join(timeout=3)

        assert len(events) >= 2
        assert events[-1]["hosts"][0]["last_seen"] >= events[0]["hosts"][0]["last_seen"]

    def test_expire_pushes_snapshot_without_host(self, live_server):
        roster, base_url, _httpd, _stop = live_server
        roster.upsert("aa:bb:cc:dd:ee:01", "old", "192.168.1.1", last_seen=time.time() - 700)
        ready = threading.Event()
        events: list[dict] = []

        def reader():
            conn = HTTPConnection("127.0.0.1", int(base_url.rsplit(":", 1)[1]), timeout=5)
            try:
                conn.request("GET", "/events")
                response = conn.getresponse()
                buffer = ""
                while len(events) < 2:
                    chunk = response.read(1)
                    if not chunk:
                        break
                    buffer += chunk.decode("utf-8", errors="replace")
                    while "\n\n" in buffer:
                        frame, buffer = buffer.split("\n\n", 1)
                        for line in frame.splitlines():
                            if line.startswith("data: "):
                                events.append(json.loads(line[6:]))
                                if len(events) == 1:
                                    ready.set()
                                break
                        if len(events) >= 2:
                            return
            finally:
                conn.close()

        thread = threading.Thread(target=reader)
        thread.start()
        assert ready.wait(timeout=3)
        roster.expire_older_than(now=time.time())
        thread.join(timeout=3)

        assert len(events) >= 2
        macs = {h["mac"] for h in events[-1]["hosts"]}
        assert "aa:bb:cc:dd:ee:01" not in macs

    def test_unknown_path_is_404(self, live_server):
        _roster, base_url, _httpd, _stop = live_server
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(base_url + "/nope", timeout=2)
        assert exc.value.code == 404


class TestBindFailure:
    def test_occupied_port_raises(self, live_server):
        _roster, base_url, httpd, _stop = live_server
        port = httpd.server_address[1]
        roster = HostRoster()
        with pytest.raises(OSError):
            start_web_server(roster, host="127.0.0.1", port=port)


class TestDisconnectHandling:
    def test_handle_error_suppresses_connection_reset(self, live_server, capsys):
        _roster, _base_url, httpd, _stop = live_server
        try:
            raise ConnectionResetError(54, "Connection reset by peer")
        except ConnectionResetError:
            httpd.handle_error(None, ("127.0.0.1", 55288))
        captured = capsys.readouterr()
        assert "Exception occurred during processing of request" not in captured.err
        assert "ConnectionResetError" not in captured.err

    def test_handle_error_still_reports_unexpected_errors(self, live_server, capsys):
        _roster, _base_url, httpd, _stop = live_server
        try:
            raise RuntimeError("unexpected")
        except RuntimeError:
            httpd.handle_error(None, ("127.0.0.1", 1))
        captured = capsys.readouterr()
        assert "Exception occurred during processing of request" in captured.err
        assert "RuntimeError" in captured.err
