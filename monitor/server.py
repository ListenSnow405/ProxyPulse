from __future__ import annotations

import json
import mimetypes
import re
import sqlite3
from dataclasses import replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .config import AppConfig
from .database import Database
from .service import MonitorService


NODE_PATH = re.compile(r"^/api/nodes/(\d+)$")
PROBE_PATH = re.compile(r"^/api/nodes/(\d+)/probe$")
class ApiError(Exception):
    def __init__(self, status: int, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.details = details


def _validate_node(payload: dict[str, Any], partial: bool = False) -> dict[str, Any]:
    allowed = {
        "name", "scheme", "host", "port", "username", "password", "enabled", "clear_credentials"
    }
    unknown = set(payload) - allowed
    if unknown:
        raise ApiError(400, f"未知字段：{', '.join(sorted(unknown))}")
    required = {"name", "scheme", "host", "port"}
    if not partial and not required.issubset(payload):
        raise ApiError(400, "节点名称、协议、主机和端口不能为空")

    result: dict[str, Any] = {}
    if "name" in payload:
        name = str(payload["name"]).strip()
        if not name or len(name) > 80:
            raise ApiError(400, "节点名称长度应为 1～80 个字符")
        result["name"] = name
    if "scheme" in payload:
        scheme = str(payload["scheme"]).lower().strip()
        if scheme in {"socks5h", "socks"}:
            scheme = "socks5"
        if scheme not in {"http", "socks5"}:
            raise ApiError(400, "目前支持 HTTP CONNECT 和 SOCKS5")
        result["scheme"] = scheme
    if "host" in payload:
        host = str(payload["host"]).strip().strip("[]")
        if not host or len(host) > 253 or any(char.isspace() for char in host):
            raise ApiError(400, "请输入有效的主机名或 IP 地址")
        if any(char in host for char in "/?#@"):
            raise ApiError(400, "主机字段不能包含 URL 路径或凭据")
        result["host"] = host
    if "port" in payload:
        try:
            port = int(payload["port"])
        except (TypeError, ValueError):
            raise ApiError(400, "端口必须是数字") from None
        if port < 1 or port > 65535:
            raise ApiError(400, "端口范围应为 1～65535")
        result["port"] = port
    for key in ("username", "password"):
        if key in payload:
            value = payload[key]
            if value is not None and len(str(value).encode("utf-8")) > 255:
                raise ApiError(400, f"{key} 不能超过 255 字节")
            result[key] = None if value is None else str(value)
    if "enabled" in payload:
        result["enabled"] = bool(payload["enabled"])
    if "clear_credentials" in payload:
        result["clear_credentials"] = bool(payload["clear_credentials"])
    return result


def _validate_settings(payload: dict[str, Any], current: dict[str, Any] | None = None) -> dict[str, Any]:
    specs: dict[str, tuple[type, float, float]] = {
        "interval_seconds": (int, 2, 3600),
        "connect_timeout_seconds": (float, 0.2, 60),
        "request_timeout_seconds": (float, 0.5, 120),
        "failure_threshold": (int, 1, 20),
        "recovery_threshold": (int, 1, 20),
        "retention_days": (int, 1, 3650),
    }
    unknown = set(payload) - set(specs) - {"targets"}
    if unknown:
        raise ApiError(400, f"未知字段：{', '.join(sorted(unknown))}")
    result: dict[str, Any] = {}
    for key, (kind, minimum, maximum) in specs.items():
        if key not in payload:
            continue
        try:
            value = kind(payload[key])
        except (TypeError, ValueError):
            raise ApiError(400, f"{key} 格式不正确") from None
        if value < minimum or value > maximum:
            raise ApiError(400, f"{key} 应在 {minimum:g}～{maximum:g} 之间")
        result[key] = value
    if "targets" in payload:
        targets = payload["targets"]
        if not isinstance(targets, list) or not 1 <= len(targets) <= 5:
            raise ApiError(400, "请设置 1～5 个测试目标")
        cleaned: list[str] = []
        for value in targets:
            target = str(value).strip()
            parsed = urlsplit(target)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ApiError(400, f"无效测试目标：{target}")
            if parsed.username or parsed.password or parsed.fragment:
                raise ApiError(400, "测试目标不能包含凭据或锚点")
            cleaned.append(target)
        result["targets"] = cleaned

    merged = {**(current or {}), **result}
    if float(merged.get("request_timeout_seconds", 8)) < float(merged.get("connect_timeout_seconds", 3)):
        raise ApiError(400, "整体超时不能短于连接超时")
    return result


def make_handler(database: Database, service: MonitorService, config: AppConfig):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ProxyPulse/0.1"

        def _origin_allowed(self) -> bool:
            origin = self.headers.get("Origin")
            if origin is None:
                return True
            try:
                parsed = urlsplit(origin)
                return (
                    parsed.scheme == "http"
                    and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                    and parsed.port in {5173, config.port}
                )
            except ValueError:
                return False

        def _cors_headers(self) -> None:
            origin = self.headers.get("Origin")
            if origin and self._origin_allowed():
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-ProxyPulse-Request")

        def _json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self._cors_headers()
            self.end_headers()
            self.wfile.write(body)

        def _error(self, error: ApiError | Exception) -> None:
            if isinstance(error, ApiError):
                payload: dict[str, Any] = {"error": error.message}
                if error.details:
                    payload["details"] = error.details
                self._json(error.status, payload)
            else:
                self._json(500, {"error": "服务器处理请求时发生错误"})

        def _body(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ApiError(400, "Content-Length 格式不正确") from None
            if length <= 0 or length > 65536:
                raise ApiError(400, "请求正文不能为空且不能超过 64 KiB")
            try:
                payload = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise ApiError(400, "请求正文必须是有效 JSON") from None
            if not isinstance(payload, dict):
                raise ApiError(400, "JSON 顶层必须是对象")
            return payload

        def _require_local_origin(self) -> None:
            if not self._origin_allowed():
                raise ApiError(403, "不允许来自其他网页的写入请求")

        def do_OPTIONS(self) -> None:  # noqa: N802
            if not self._origin_allowed():
                self._json(403, {"error": "origin not allowed"})
                return
            self.send_response(204)
            self._cors_headers()
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            try:
                parsed = urlsplit(self.path)
                if parsed.path == "/api/status":
                    self._json(200, {"monitor": service.status(), "version": "0.1.0"})
                elif parsed.path == "/api/settings":
                    self._json(200, {"settings": database.get_settings()})
                elif parsed.path == "/api/nodes":
                    self._json(200, {"nodes": database.list_nodes()})
                elif parsed.path == "/api/dashboard":
                    query = parse_qs(parsed.query)
                    window = max(3600, min(30 * 86400, int(query.get("window", [86400])[0])))
                    points = max(120, min(1440, int(query.get("points", [720])[0])))
                    selected = query.get("node_id", [None])[0]
                    node_id = int(selected) if selected not in {None, ""} else None
                    data = database.dashboard(window, node_id, points)
                    data["monitor"] = service.status()
                    self._json(200, data)
                elif NODE_PATH.match(parsed.path):
                    node_id = int(NODE_PATH.match(parsed.path).group(1))  # type: ignore[union-attr]
                    node = database.get_node(node_id)
                    if node is None:
                        raise ApiError(404, "未找到该节点")
                    self._json(200, {"node": node})
                elif parsed.path.startswith("/api/"):
                    raise ApiError(404, "未找到该接口")
                else:
                    self._serve_static(parsed.path)
            except (ValueError, ApiError) as error:
                self._error(error if isinstance(error, ApiError) else ApiError(400, "查询参数格式不正确"))
            except Exception as error:
                self.log_error("GET failed: %s", error)
                self._error(error)

        def do_POST(self) -> None:  # noqa: N802
            try:
                self._require_local_origin()
                path = urlsplit(self.path).path
                if path == "/api/nodes":
                    node = database.create_node(_validate_node(self._body()))
                    service.wake()
                    self._json(201, {"node": node})
                    return
                match = PROBE_PATH.match(path)
                if match:
                    node_id = int(match.group(1))
                    if database.get_node(node_id) is None:
                        raise ApiError(404, "未找到该节点")
                    result = service.run_node_now(node_id)
                    self._json(200, {"probe": result})
                    return
                raise ApiError(404, "未找到该接口")
            except sqlite3.IntegrityError as error:
                self._error(ApiError(409, "节点名称已存在，或节点配置不合法", {"reason": str(error)}))
            except Exception as error:
                if not isinstance(error, ApiError):
                    self.log_error("POST failed: %s", error)
                self._error(error)

        def do_PUT(self) -> None:  # noqa: N802
            self._handle_update()

        def do_PATCH(self) -> None:  # noqa: N802
            self._handle_update()

        def _handle_update(self) -> None:
            try:
                self._require_local_origin()
                path = urlsplit(self.path).path
                if path == "/api/settings":
                    settings = database.update_settings(
                        _validate_settings(self._body(), database.get_settings())
                    )
                    service.wake()
                    self._json(200, {"settings": settings})
                    return
                match = NODE_PATH.match(path)
                if match:
                    node_id = int(match.group(1))
                    node = database.update_node(node_id, _validate_node(self._body(), partial=True))
                    if node is None:
                        raise ApiError(404, "未找到该节点")
                    service.wake()
                    self._json(200, {"node": node})
                    return
                raise ApiError(404, "未找到该接口")
            except sqlite3.IntegrityError as error:
                self._error(ApiError(409, "节点名称已存在，或节点配置不合法", {"reason": str(error)}))
            except Exception as error:
                if not isinstance(error, ApiError):
                    self.log_error("update failed: %s", error)
                self._error(error)

        def do_DELETE(self) -> None:  # noqa: N802
            try:
                self._require_local_origin()
                match = NODE_PATH.match(urlsplit(self.path).path)
                if not match:
                    raise ApiError(404, "未找到该接口")
                if not database.delete_node(int(match.group(1))):
                    raise ApiError(404, "未找到该节点")
                self.send_response(204)
                self._cors_headers()
                self.send_header("Content-Length", "0")
                self.end_headers()
            except Exception as error:
                self._error(error)

        def _serve_static(self, request_path: str) -> None:
            root = config.static_path.resolve()
            relative = unquote(request_path).lstrip("/") or "index.html"
            candidate = (root / relative).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                raise ApiError(403, "禁止访问该路径") from None
            if candidate.is_dir():
                candidate = candidate / "index.html"
            if not candidate.is_file() and "." not in Path(relative).name:
                candidate = root / "index.html"
            if not candidate.is_file():
                if relative == "index.html":
                    self._json(
                        503,
                        {
                            "error": "网页尚未构建",
                            "hint": "开发时打开 http://127.0.0.1:5173，或先运行 npm run build",
                        },
                    )
                    return
                raise ApiError(404, "未找到文件")
            body = candidate.read_bytes()
            content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
                content_type += "; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache" if candidate.name == "index.html" else "public, max-age=31536000, immutable")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            # Keep routine polling quiet; unexpected server errors still use log_error.
            if len(args) > 1 and str(args[1]) >= "400":
                super().log_message(format, *args)

    return Handler


def create_server(database: Database, service: MonitorService, config: AppConfig) -> ThreadingHTTPServer:
    if config.host not in {"127.0.0.1", "localhost"}:
        raise ValueError("ProxyPulse only accepts loopback listen addresses in local mode")
    return ThreadingHTTPServer((config.host, config.port), make_handler(database, service, config))
