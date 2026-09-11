from __future__ import annotations

import select
import socket
import socketserver
import tempfile
import threading
import time
import unittest
import json
import urllib.request
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from monitor.config import AppConfig
from monitor.database import Database
from monitor.probe import ProbeSettings, probe_proxy
from monitor.server import create_server
from monitor.service import MonitorService


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("X-Test", "ok")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


def recv_until(sock: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    data = bytearray()
    while marker not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def relay(client: socket.socket, upstream: socket.socket) -> None:
    sockets = [client, upstream]
    while sockets:
        readable, _, _ = select.select(sockets, [], [], 1)
        if not readable:
            continue
        for source in readable:
            try:
                chunk = source.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            destination = upstream if source is client else client
            destination.sendall(chunk)


class ConnectProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        request = recv_until(self.request, b"\r\n\r\n")
        first_line = request.split(b"\r\n", 1)[0].decode("ascii")
        authority = first_line.split(" ")[1]
        host, port = authority.rsplit(":", 1)
        upstream = socket.create_connection((host.strip("[]"), int(port)), timeout=2)
        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            relay(self.request, upstream)
        finally:
            upstream.close()


class SocksProxyHandler(socketserver.BaseRequestHandler):
    def _exact(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = self.request.recv(size - len(data))
            if not chunk:
                raise ConnectionError("early eof")
            data.extend(chunk)
        return bytes(data)

    def handle(self) -> None:
        version, method_count = self._exact(2)
        assert version == 5
        self._exact(method_count)
        self.request.sendall(b"\x05\x00")
        version, command, _, address_type = self._exact(4)
        assert version == 5 and command == 1
        if address_type == 1:
            host = socket.inet_ntoa(self._exact(4))
        elif address_type == 3:
            host = self._exact(self._exact(1)[0]).decode("idna")
        else:
            raise AssertionError("unsupported test address type")
        port = int.from_bytes(self._exact(2), "big")
        upstream = socket.create_connection((host, port), timeout=2)
        try:
            self.request.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            relay(self.request, upstream)
        finally:
            upstream.close()


class SlowProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        recv_until(self.request, b"\r\n\r\n")
        time.sleep(0.4)


class ProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
        self.target_thread = threading.Thread(target=self.target.serve_forever, daemon=True)
        self.target_thread.start()

    def tearDown(self) -> None:
        self.target.shutdown()
        self.target.server_close()

    def _run_proxy(self, handler: type[socketserver.BaseRequestHandler]):
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_http_connect_probe(self) -> None:
        proxy = self._run_proxy(ConnectProxyHandler)
        result = probe_proxy(
            {"scheme": "http", "host": "127.0.0.1", "port": proxy.server_address[1]},
            f"http://127.0.0.1:{self.target.server_port}/health",
            ProbeSettings(1, 2),
        )
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["http_status"], 204)
        self.assertIsNotNone(result["tcp_ms"])
        self.assertIsNotNone(result["proxy_ms"])
        self.assertIsNotNone(result["ttfb_ms"])

    def test_socks5_probe(self) -> None:
        proxy = self._run_proxy(SocksProxyHandler)
        result = probe_proxy(
            {"scheme": "socks5", "host": "127.0.0.1", "port": proxy.server_address[1]},
            f"http://localhost:{self.target.server_port}/health",
            ProbeSettings(1, 2),
        )
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["http_status"], 204)

    def test_proxy_handshake_timeout_is_classified(self) -> None:
        proxy = self._run_proxy(SlowProxyHandler)
        result = probe_proxy(
            {"scheme": "http", "host": "127.0.0.1", "port": proxy.server_address[1]},
            f"http://127.0.0.1:{self.target.server_port}/health",
            ProbeSettings(0.1, 0.15),
        )
        self.assertEqual(result["outcome"], "timeout")
        self.assertEqual(result["timeout_phase"], "proxy_handshake")


def result(outcome: str, timestamp: str, latency: float | None = None) -> dict[str, object]:
    return {
        "target": "http://target.test/health",
        "started_at": timestamp,
        "completed_at": timestamp,
        "outcome": outcome,
        "timeout_phase": "connect" if outcome == "timeout" else None,
        "tcp_ms": latency,
        "proxy_ms": None,
        "tls_ms": None,
        "ttfb_ms": None,
        "total_ms": latency or 100.0,
        "http_status": 204 if outcome == "success" else None,
        "error_type": "timeout" if outcome == "timeout" else None,
        "error_message": "timed out" if outcome == "timeout" else None,
    }


class DatabaseStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        config = replace(AppConfig(), database_path=Path(self.temp.name) / "monitor.db")
        self.database = Database(config.database_path)
        self.database.initialize(config)
        self.node = self.database.create_node({
            "name": "Test node", "scheme": "http", "host": "127.0.0.1", "port": 8080,
        })

    def tearDown(self) -> None:
        self.temp.cleanup()

    def record(self, index: int, outcome: str) -> None:
        timestamp = f"2026-01-01T00:00:{index:02d}.000Z"
        sample = result(outcome, timestamp, 42 if outcome == "success" else None)
        aggregate = {
            "started_at": timestamp, "completed_at": timestamp, "outcome": outcome,
            "latency_ms": 42 if outcome == "success" else None,
            "timeout_phase": "connect" if outcome == "timeout" else None,
            "error_type": "timeout" if outcome == "timeout" else None,
            "error_message": "timed out" if outcome == "timeout" else None,
        }
        self.database.record_cycle(self.node["id"], f"cycle-{index}", [sample], aggregate, 3, 2)

    def test_secrets_are_redacted(self) -> None:
        self.database.update_node(self.node["id"], {"username": "user", "password": "secret"})
        public = self.database.get_node(self.node["id"])
        self.assertNotIn("password", public)
        self.assertNotIn("username", public)
        self.assertTrue(public["has_username"])
        self.assertTrue(public["has_password"])
        private = self.database.get_node(self.node["id"], include_secrets=True)
        self.assertEqual(private["username"], "user")
        self.assertEqual(private["password"], "secret")
        with self.database.connect() as connection:
            stored = connection.execute(
                "SELECT username, password FROM nodes WHERE id = ?", (self.node["id"],)
            ).fetchone()
        self.assertNotEqual(stored["username"], "user")
        self.assertNotEqual(stored["password"], "secret")

        self.database.update_node(self.node["id"], {"clear_credentials": True})
        cleared = self.database.get_node(self.node["id"])
        self.assertFalse(cleared["has_username"])
        self.assertFalse(cleared["has_password"])

    def test_incident_start_and_end_are_backdated(self) -> None:
        self.record(0, "timeout")
        self.record(10, "timeout")
        self.record(20, "timeout")
        with self.database.connect() as connection:
            incident = dict(connection.execute("SELECT * FROM incidents").fetchone())
        self.assertEqual(incident["started_at"], "2026-01-01T00:00:00.000Z")
        self.assertEqual(incident["confirmed_at"], "2026-01-01T00:00:20.000Z")
        self.assertEqual(incident["status"], "open")

        self.record(30, "success")
        self.record(40, "timeout")
        self.record(50, "success")
        self.record(59, "success")
        with self.database.connect() as connection:
            incident = dict(connection.execute("SELECT * FROM incidents").fetchone())
            state = dict(connection.execute("SELECT * FROM node_states").fetchone())
        self.assertEqual(incident["ended_at"], "2026-01-01T00:00:50.000Z")
        self.assertEqual(incident["recovery_confirmed_at"], "2026-01-01T00:00:59.000Z")
        self.assertEqual(incident["status"], "closed")
        self.assertEqual(state["status"], "healthy")

    def test_monitor_gap_does_not_extend_an_outage(self) -> None:
        self.record(0, "timeout")
        self.record(10, "timeout")
        self.record(20, "timeout")
        self.record(59, "success")
        with self.database.connect() as connection:
            incident = dict(connection.execute("SELECT * FROM incidents").fetchone())
            state = dict(connection.execute("SELECT * FROM node_states").fetchone())
        self.assertEqual(incident["ended_at"], "2026-01-01T00:00:20.000Z")
        self.assertEqual(incident["end_confirmed"], 0)
        self.assertEqual(incident["close_reason"], "monitor_gap")
        self.assertEqual(state["status"], "healthy")

    def test_mixed_failures_are_not_labeled_as_pure_timeout(self) -> None:
        self.record(0, "timeout")
        self.record(10, "error")
        self.record(20, "timeout")
        with self.database.connect() as connection:
            incident = dict(connection.execute("SELECT * FROM incidents").fetchone())
        self.assertEqual(incident["category"], "error")


class ServiceAggregationTests(unittest.TestCase):
    @staticmethod
    def sample(outcome: str, total_ms: float, *, error_type: str | None = None) -> dict[str, object]:
        return {
            "target": "http://target.test/", "started_at": "2026-01-01T00:00:00.000Z",
            "completed_at": "2026-01-01T00:00:00.100Z", "outcome": outcome,
            "total_ms": total_ms, "timeout_phase": "connect" if outcome == "timeout" else None,
            "error_type": error_type, "error_message": error_type,
        }

    def test_fallback_proves_reachability_without_changing_latency_target(self) -> None:
        aggregate = MonitorService._aggregate([
            self.sample("timeout", 500, error_type="timeout"),
            self.sample("success", 35),
        ])
        self.assertEqual(aggregate["outcome"], "success")
        self.assertIsNone(aggregate["latency_ms"])
        self.assertEqual(aggregate["error_type"], "partial_target_failure")

        aggregate = MonitorService._aggregate([
            self.sample("success", 42),
            self.sample("timeout", 500, error_type="timeout"),
        ])
        self.assertEqual(aggregate["latency_ms"], 42)


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.config = replace(
            AppConfig(),
            database_path=Path(self.temp.name) / "api.db",
            static_path=Path(self.temp.name) / "static",
            port=0,
        )
        self.database = Database(self.config.database_path)
        self.database.initialize(self.config)
        self.service = MonitorService(self.database)
        self.server = create_server(self.database, self.service, self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.service.stop()
        self.temp.cleanup()

    def request(self, path: str, method: str = "GET", payload: dict[str, object] | None = None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            self.base + path,
            data=data,
            method=method,
            headers={
                "Content-Type": "application/json",
                "Origin": "http://127.0.0.1:5173",
                "X-ProxyPulse-Request": "1",
            },
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read()) if response.status != 204 else None

    def test_node_crud_and_dashboard(self) -> None:
        status, created = self.request("/api/nodes", "POST", {
            "name": "API node", "scheme": "socks5", "host": "127.0.0.1", "port": 1080,
            "password": "do-not-return", "enabled": False,
        })
        self.assertEqual(status, 201)
        node_id = created["node"]["id"]
        self.assertNotIn("password", created["node"])
        self.assertTrue(created["node"]["has_password"])

        _, dashboard = self.request(f"/api/dashboard?window=3600&node_id={node_id}")
        self.assertEqual(dashboard["selected_node_id"], node_id)
        self.assertEqual(dashboard["nodes"][0]["name"], "API node")

        _, updated = self.request(f"/api/nodes/{node_id}", "PUT", {"name": "Renamed node"})
        self.assertEqual(updated["node"]["name"], "Renamed node")
        status, _ = self.request(f"/api/nodes/{node_id}", "DELETE")
        self.assertEqual(status, 204)


if __name__ == "__main__":
    unittest.main()
