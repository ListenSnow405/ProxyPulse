from __future__ import annotations

import base64
import ipaddress
import socket
import ssl
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit


class ProbeFailure(Exception):
    """An expected proxy negotiation or response failure."""

    def __init__(self, message: str, error_type: str = "probe_error") -> None:
        super().__init__(message)
        self.error_type = error_type


@dataclass(frozen=True)
class ProbeSettings:
    connect_timeout_seconds: float
    request_timeout_seconds: float


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _remaining(deadline: float, cap: float | None = None) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("overall request deadline exceeded")
    return min(remaining, cap) if cap is not None else remaining


def _recv_exact(sock: socket.socket, size: int, deadline: float) -> bytes:
    chunks: list[bytes] = []
    remaining_size = size
    while remaining_size:
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(remaining_size)
        if not chunk:
            raise ProbeFailure("proxy closed the connection", "connection_closed")
        chunks.append(chunk)
        remaining_size -= len(chunk)
    return b"".join(chunks)


def _recv_headers(sock: socket.socket, deadline: float, limit: int = 65536) -> tuple[bytes, float]:
    data = bytearray()
    first_byte_at: float | None = None
    while b"\r\n\r\n" not in data:
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(min(4096, limit - len(data)))
        if not chunk:
            raise ProbeFailure("remote closed before sending complete HTTP headers", "invalid_response")
        if first_byte_at is None:
            first_byte_at = time.monotonic()
        data.extend(chunk)
        if len(data) >= limit:
            raise ProbeFailure("HTTP response headers exceeded 64 KiB", "invalid_response")
    return bytes(data), first_byte_at or time.monotonic()


def _http_connect(
    sock: socket.socket,
    node: dict[str, Any],
    target_host: str,
    target_port: int,
    deadline: float,
) -> None:
    authority_host = f"[{target_host}]" if ":" in target_host else target_host
    authority = f"{authority_host}:{target_port}"
    headers = [
        f"CONNECT {authority} HTTP/1.1",
        f"Host: {authority}",
        "Proxy-Connection: keep-alive",
        "User-Agent: ProxyPulse/0.1",
    ]
    if node.get("username"):
        token = base64.b64encode(
            f"{node['username']}:{node.get('password') or ''}".encode("utf-8")
        ).decode("ascii")
        headers.append(f"Proxy-Authorization: Basic {token}")
    request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
    sock.settimeout(_remaining(deadline))
    sock.sendall(request)
    response, _ = _recv_headers(sock, deadline)
    status_line = response.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise ProbeFailure(f"invalid proxy response: {status_line[:120]}", "invalid_proxy_response")
    status = int(parts[1])
    if status == 407:
        raise ProbeFailure("proxy authentication rejected", "proxy_auth")
    if status < 200 or status >= 300:
        raise ProbeFailure(f"proxy CONNECT returned HTTP {status}", "proxy_connect")


def _socks_address(host: str) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise ProbeFailure("target hostname is too long for SOCKS5", "invalid_target")
        return b"\x03" + bytes([len(encoded)]) + encoded
    if address.version == 4:
        return b"\x01" + address.packed
    return b"\x04" + address.packed


def _socks5_connect(
    sock: socket.socket,
    node: dict[str, Any],
    target_host: str,
    target_port: int,
    deadline: float,
) -> None:
    has_auth = bool(node.get("username"))
    methods = b"\x00\x02" if has_auth else b"\x00"
    sock.settimeout(_remaining(deadline))
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    response = _recv_exact(sock, 2, deadline)
    if response[0] != 5:
        raise ProbeFailure("proxy did not speak SOCKS5", "invalid_proxy_response")
    if response[1] == 0xFF:
        raise ProbeFailure("SOCKS5 proxy has no acceptable authentication method", "proxy_auth")
    if response[1] == 0x02:
        username = (node.get("username") or "").encode("utf-8")
        password = (node.get("password") or "").encode("utf-8")
        if not username or len(username) > 255 or len(password) > 255:
            raise ProbeFailure("invalid SOCKS5 username or password length", "proxy_auth")
        sock.sendall(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
        auth_response = _recv_exact(sock, 2, deadline)
        if auth_response[1] != 0:
            raise ProbeFailure("SOCKS5 authentication rejected", "proxy_auth")
    elif response[1] != 0x00:
        raise ProbeFailure(f"unsupported SOCKS5 authentication method {response[1]}", "proxy_auth")

    request = b"\x05\x01\x00" + _socks_address(target_host) + struct.pack("!H", target_port)
    sock.sendall(request)
    reply = _recv_exact(sock, 4, deadline)
    if reply[0] != 5:
        raise ProbeFailure("invalid SOCKS5 connect response", "invalid_proxy_response")
    if reply[1] != 0:
        names = {
            1: "general failure",
            2: "connection not allowed",
            3: "network unreachable",
            4: "host unreachable",
            5: "connection refused",
            6: "TTL expired",
            7: "command not supported",
            8: "address type not supported",
        }
        raise ProbeFailure(f"SOCKS5 connect failed: {names.get(reply[1], reply[1])}", "proxy_connect")
    atyp = reply[3]
    if atyp == 1:
        _recv_exact(sock, 4, deadline)
    elif atyp == 4:
        _recv_exact(sock, 16, deadline)
    elif atyp == 3:
        length = _recv_exact(sock, 1, deadline)[0]
        _recv_exact(sock, length, deadline)
    else:
        raise ProbeFailure("invalid SOCKS5 bound address", "invalid_proxy_response")
    _recv_exact(sock, 2, deadline)


def probe_proxy(node: dict[str, Any], target: str, settings: ProbeSettings) -> dict[str, Any]:
    """Perform one end-to-end request through a proxy and return phase timings."""

    started_at = utc_now()
    started = time.monotonic()
    deadline = started + settings.request_timeout_seconds
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("probe targets must be absolute http:// or https:// URLs")

    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    result: dict[str, Any] = {
        "target": target,
        "started_at": started_at,
        "completed_at": None,
        "outcome": "error",
        "timeout_phase": None,
        "tcp_ms": None,
        "proxy_ms": None,
        "tls_ms": None,
        "ttfb_ms": None,
        "total_ms": None,
        "http_status": None,
        "error_type": None,
        "error_message": None,
    }

    sock: socket.socket | ssl.SSLSocket | None = None
    phase = "connect"
    try:
        phase_started = time.monotonic()
        sock = socket.create_connection(
            (node["host"], int(node["port"])),
            timeout=_remaining(deadline, settings.connect_timeout_seconds),
        )
        result["tcp_ms"] = round((time.monotonic() - phase_started) * 1000, 2)

        phase = "proxy_handshake"
        phase_started = time.monotonic()
        scheme = str(node["scheme"]).lower()
        if scheme == "http":
            _http_connect(sock, node, parsed.hostname, target_port, deadline)
        elif scheme in {"socks5", "socks5h"}:
            _socks5_connect(sock, node, parsed.hostname, target_port, deadline)
        else:
            raise ProbeFailure(f"unsupported proxy scheme: {scheme}", "unsupported_proxy")
        result["proxy_ms"] = round((time.monotonic() - phase_started) * 1000, 2)

        if parsed.scheme == "https":
            phase = "tls"
            phase_started = time.monotonic()
            sock.settimeout(_remaining(deadline))
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
            result["tls_ms"] = round((time.monotonic() - phase_started) * 1000, 2)

        phase = "first_byte"
        host_header = parsed.hostname
        if target_port not in {80, 443}:
            host_header = f"{host_header}:{target_port}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: ProxyPulse/0.1\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.settimeout(_remaining(deadline))
        sent_at = time.monotonic()
        sock.sendall(request)
        response, first_byte_at = _recv_headers(sock, deadline)
        result["ttfb_ms"] = round((first_byte_at - sent_at) * 1000, 2)

        status_line = response.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise ProbeFailure(f"invalid target response: {status_line[:120]}", "invalid_response")
        result["http_status"] = int(parts[1])
        result["outcome"] = "success"
    except (socket.timeout, TimeoutError) as exc:
        result["outcome"] = "timeout"
        result["timeout_phase"] = phase
        result["error_type"] = "timeout"
        result["error_message"] = str(exc) or f"{phase} timed out"
    except socket.gaierror as exc:
        result["error_type"] = "dns"
        result["error_message"] = str(exc)
    except ConnectionRefusedError as exc:
        result["error_type"] = "connection_refused"
        result["error_message"] = str(exc)
    except ssl.SSLError as exc:
        result["error_type"] = "tls"
        result["error_message"] = str(exc)
    except ProbeFailure as exc:
        result["error_type"] = exc.error_type
        result["error_message"] = str(exc)
    except OSError as exc:
        result["error_type"] = "network"
        result["error_message"] = str(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        result["completed_at"] = utc_now()
        result["total_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result
