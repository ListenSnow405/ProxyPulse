from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ is required.
    tomllib = None  # type: ignore[assignment]


DEFAULT_TARGETS = [
    "https://cp.cloudflare.com/generate_204",
    "https://www.apple.com/library/test/success.html",
]


@dataclass(frozen=True)
class AppConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    database_path: Path = Path("data/proxy-monitor.db")
    static_path: Path = Path("dist/client")
    interval_seconds: int = 10
    connect_timeout_seconds: float = 3.0
    request_timeout_seconds: float = 8.0
    failure_threshold: int = 3
    recovery_threshold: int = 2
    retention_days: int = 30
    targets: list[str] = field(default_factory=lambda: list(DEFAULT_TARGETS))


def load_config(path: str | Path | None = None) -> AppConfig:
    """Load optional TOML configuration and apply safe environment overrides."""

    config_path = Path(path or os.environ.get("PROXY_MONITOR_CONFIG", "config.toml"))
    raw: dict = {}
    if config_path.exists():
        if tomllib is None:
            raise RuntimeError("Python 3.11 or newer is required to read config.toml")
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)

    server = raw.get("server", {})
    monitor = raw.get("monitor", {})
    storage = raw.get("storage", {})

    root = config_path.resolve().parent
    database_path = Path(
        os.environ.get(
            "PROXY_MONITOR_DB",
            storage.get("database_path", "data/proxy-monitor.db"),
        )
    )
    static_path = Path(server.get("static_path", "dist/client"))
    if not database_path.is_absolute():
        database_path = root / database_path
    if not static_path.is_absolute():
        static_path = root / static_path

    return AppConfig(
        host=os.environ.get("PROXY_MONITOR_HOST", server.get("host", "127.0.0.1")),
        port=int(os.environ.get("PROXY_MONITOR_PORT", server.get("port", 8765))),
        database_path=database_path,
        static_path=static_path,
        interval_seconds=int(monitor.get("interval_seconds", 10)),
        connect_timeout_seconds=float(monitor.get("connect_timeout_seconds", 3.0)),
        request_timeout_seconds=float(monitor.get("request_timeout_seconds", 8.0)),
        failure_threshold=int(monitor.get("failure_threshold", 3)),
        recovery_threshold=int(monitor.get("recovery_threshold", 2)),
        retention_days=int(monitor.get("retention_days", 30)),
        targets=list(monitor.get("targets", DEFAULT_TARGETS)),
    )
