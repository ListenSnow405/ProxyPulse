from __future__ import annotations

import json
import math
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .config import AppConfig
from .secrets import is_protected, protect_secret, reveal_secret


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    scheme TEXT NOT NULL CHECK (scheme IN ('http', 'socks5')),
    host TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    username TEXT,
    password TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS node_checks (
    id INTEGER PRIMARY KEY,
    cycle_id TEXT NOT NULL,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'timeout', 'error')),
    latency_ms REAL,
    timeout_phase TEXT,
    error_type TEXT,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS probe_results (
    id INTEGER PRIMARY KEY,
    cycle_id TEXT NOT NULL,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'timeout', 'error')),
    timeout_phase TEXT,
    tcp_ms REAL,
    proxy_ms REAL,
    tls_ms REAL,
    ttfb_ms REAL,
    total_ms REAL,
    http_status INTEGER,
    error_type TEXT,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    confirmed_at TEXT NOT NULL,
    ended_at TEXT,
    recovery_confirmed_at TEXT,
    last_failure_at TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('timeout', 'error')),
    timeout_phase TEXT,
    failure_count INTEGER NOT NULL DEFAULT 0,
    recovery_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    end_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (end_confirmed IN (0, 1)),
    close_reason TEXT
);

CREATE TABLE IF NOT EXISTS node_states (
    node_id INTEGER PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'healthy', 'suspect', 'down', 'recovering')),
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    consecutive_successes INTEGER NOT NULL DEFAULT 0,
    candidate_started_at TEXT,
    recovery_started_at TEXT,
    current_incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    last_result_at TEXT,
    last_latency_ms REAL,
    last_outcome TEXT,
    last_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_node_checks_node_started
ON node_checks(node_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_probe_results_node_started
ON probe_results(node_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_node_started
ON incidents(node_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_open
ON incidents(node_id, status)
WHERE status = 'open';
"""


PROBE_COLUMNS = [
    "target",
    "started_at",
    "completed_at",
    "outcome",
    "timeout_phase",
    "tcp_ms",
    "proxy_ms",
    "tls_ms",
    "ttfb_ms",
    "total_ms",
    "http_status",
    "error_type",
    "error_message",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _iso_from_epoch(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _epoch(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[index], 2)


class _ClosingConnection(sqlite3.Connection):
    """Make a connection context close handles as well as transactions."""

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, traceback))
        finally:
            self.close()


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, factory=_ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def initialize(self, config: AppConfig) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(SCHEMA)
            # Correct the two numeric affinities in databases created by early builds.
            columns = {row[1] for row in connection.execute("PRAGMA table_info(probe_results)")}
            if not {"tls_ms", "total_ms"}.issubset(columns):
                raise RuntimeError("probe_results schema is missing timing columns")
            incident_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(incidents)")
            }
            if "end_confirmed" not in incident_columns:
                connection.execute(
                    "ALTER TABLE incidents ADD COLUMN end_confirmed INTEGER NOT NULL DEFAULT 0"
                )
            if "close_reason" not in incident_columns:
                connection.execute("ALTER TABLE incidents ADD COLUMN close_reason TEXT")
            defaults = {
                "interval_seconds": config.interval_seconds,
                "connect_timeout_seconds": config.connect_timeout_seconds,
                "request_timeout_seconds": config.request_timeout_seconds,
                "failure_threshold": config.failure_threshold,
                "recovery_threshold": config.recovery_threshold,
                "retention_days": config.retention_days,
                "targets": config.targets,
            }
            for key, value in defaults.items():
                connection.execute(
                    "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)",
                    (key, json.dumps(value, ensure_ascii=False)),
                )
            for row in connection.execute(
                "SELECT id, username, password FROM nodes "
                "WHERE (username IS NOT NULL AND username != '') "
                "OR (password IS NOT NULL AND password != '')"
            ).fetchall():
                username = row["username"]
                password = row["password"]
                if not is_protected(username) or not is_protected(password):
                    connection.execute(
                        "UPDATE nodes SET username = ?, password = ? WHERE id = ?",
                        (
                            username if is_protected(username) else protect_secret(username),
                            password if is_protected(password) else protect_secret(password),
                            row["id"],
                        ),
                    )
            connection.execute("PRAGMA optimize")

    def get_settings(self) -> dict[str, Any]:
        with self.connect() as connection:
            rows = connection.execute("SELECT key, value FROM settings").fetchall()
        return {row["key"]: json.loads(row["value"]) for row in rows}

    def update_settings(self, values: dict[str, Any]) -> dict[str, Any]:
        with self.connect() as connection:
            for key, value in values.items():
                connection.execute(
                    "INSERT INTO settings(key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, json.dumps(value, ensure_ascii=False)),
                )
        return self.get_settings()

    @staticmethod
    def _public_node(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        item["has_username"] = bool(item.get("username"))
        item["has_password"] = bool(item.get("password"))
        item.pop("username", None)
        item.pop("password", None)
        return item

    def list_nodes(self, include_secrets: bool = False) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT n.*, s.status, s.consecutive_failures, s.consecutive_successes, "
                "s.last_result_at, s.last_latency_ms, s.last_outcome, s.last_error, "
                "s.current_incident_id "
                "FROM nodes n LEFT JOIN node_states s ON s.node_id = n.id "
                "ORDER BY n.name COLLATE NOCASE"
            ).fetchall()
        if include_secrets:
            result = [dict(row) for row in rows]
            for item in result:
                item["enabled"] = bool(item["enabled"])
                item["username"] = reveal_secret(item.get("username"))
                item["password"] = reveal_secret(item.get("password"))
            return result
        return [self._public_node(row) for row in rows]

    def get_node(self, node_id: int, include_secrets: bool = False) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        if include_secrets:
            item["username"] = reveal_secret(item.get("username"))
            item["password"] = reveal_secret(item.get("password"))
        return item if include_secrets else self._public_node(item)

    def create_node(self, values: dict[str, Any]) -> dict[str, Any]:
        now = _utc_now()
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO nodes(name, scheme, host, port, username, password, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    values["name"], values["scheme"], values["host"], values["port"],
                    protect_secret(values.get("username")), protect_secret(values.get("password")), int(values.get("enabled", True)),
                    now, now,
                ),
            )
            node_id = int(cursor.lastrowid)
            connection.execute("INSERT INTO node_states(node_id) VALUES (?)", (node_id,))
        node = self.get_node(node_id)
        assert node is not None
        return node

    def update_node(self, node_id: int, values: dict[str, Any]) -> dict[str, Any] | None:
        current = self.get_node(node_id, include_secrets=True)
        if current is None:
            return None
        merged = {**current, **values}
        # An omitted or blank password in an edit keeps the existing secret.
        if values.get("password") in {None, ""}:
            merged["password"] = current.get("password")
        if values.get("clear_credentials"):
            merged["username"] = None
            merged["password"] = None
        with self.connect() as connection:
            connection.execute(
                "UPDATE nodes SET name = ?, scheme = ?, host = ?, port = ?, username = ?, "
                "password = ?, enabled = ?, updated_at = ? WHERE id = ?",
                (
                    merged["name"], merged["scheme"], merged["host"], merged["port"],
                    protect_secret(merged.get("username")), protect_secret(merged.get("password")), int(merged.get("enabled", True)),
                    _utc_now(), node_id,
                ),
            )
            if current.get("enabled") and not merged.get("enabled", True):
                state = connection.execute(
                    "SELECT current_incident_id, last_result_at FROM node_states WHERE node_id = ?",
                    (node_id,),
                ).fetchone()
                if state and state["current_incident_id"]:
                    ended_at = state["last_result_at"] or _utc_now()
                    connection.execute(
                        "UPDATE incidents SET ended_at = ?, status = 'closed', end_confirmed = 0, "
                        "close_reason = 'node_disabled' WHERE id = ?",
                        (ended_at, state["current_incident_id"]),
                    )
                connection.execute(
                    "UPDATE node_states SET status = 'unknown', consecutive_failures = 0, "
                    "consecutive_successes = 0, candidate_started_at = NULL, "
                    "recovery_started_at = NULL, current_incident_id = NULL WHERE node_id = ?",
                    (node_id,),
                )
        return self.get_node(node_id)

    def delete_node(self, node_id: int) -> bool:
        with self.connect() as connection:
            cursor = connection.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
        return cursor.rowcount > 0

    def record_cycle(
        self,
        node_id: int,
        cycle_id: str,
        results: list[dict[str, Any]],
        aggregate: dict[str, Any],
        failure_threshold: int,
        recovery_threshold: int,
        interval_seconds: int = 10,
    ) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO node_checks(cycle_id, node_id, started_at, completed_at, outcome, latency_ms, "
                "timeout_phase, error_type, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    cycle_id, node_id, aggregate["started_at"], aggregate["completed_at"],
                    aggregate["outcome"], aggregate.get("latency_ms"), aggregate.get("timeout_phase"),
                    aggregate.get("error_type"), aggregate.get("error_message"),
                ),
            )
            for result in results:
                connection.execute(
                    "INSERT INTO probe_results(cycle_id, node_id, target, started_at, completed_at, outcome, "
                    "timeout_phase, tcp_ms, proxy_ms, tls_ms, ttfb_ms, total_ms, http_status, error_type, error_message) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        cycle_id, node_id, result["target"], result["started_at"], result["completed_at"],
                        result["outcome"], result.get("timeout_phase"), result.get("tcp_ms"),
                        result.get("proxy_ms"), result.get("tls_ms"), result.get("ttfb_ms"),
                        result.get("total_ms"), result.get("http_status"), result.get("error_type"),
                        result.get("error_message"),
                    ),
                )

            state_row = connection.execute(
                "SELECT * FROM node_states WHERE node_id = ?", (node_id,)
            ).fetchone()
            if state_row is None:
                connection.execute("INSERT INTO node_states(node_id) VALUES (?)", (node_id,))
                state_row = connection.execute(
                    "SELECT * FROM node_states WHERE node_id = ?", (node_id,)
                ).fetchone()
            assert state_row is not None
            state = dict(state_row)
            if state.get("last_result_at"):
                observation_gap = _epoch(aggregate["started_at"]) - _epoch(state["last_result_at"])
                if observation_gap > max(5.0, interval_seconds * 2.5):
                    if state.get("current_incident_id"):
                        connection.execute(
                            "UPDATE incidents SET ended_at = ?, status = 'closed', end_confirmed = 0, "
                            "close_reason = 'monitor_gap' WHERE id = ?",
                            (state["last_result_at"], state["current_incident_id"]),
                        )
                    state.update(
                        status="unknown",
                        consecutive_failures=0,
                        consecutive_successes=0,
                        candidate_started_at=None,
                        recovery_started_at=None,
                        current_incident_id=None,
                    )
            is_success = aggregate["outcome"] == "success"

            if not is_success:
                failures = int(state["consecutive_failures"] or 0) + 1
                candidate = state["candidate_started_at"] or aggregate["started_at"]
                current_incident_id = state["current_incident_id"]
                status = "suspect"
                if current_incident_id:
                    status = "down"
                    connection.execute(
                        "UPDATE incidents SET last_failure_at = ?, failure_count = failure_count + 1, "
                        "last_error = ?, recovery_count = 0 WHERE id = ?",
                        (aggregate["started_at"], aggregate.get("error_message"), current_incident_id),
                    )
                elif failures >= failure_threshold:
                    failure_rows = connection.execute(
                        "SELECT outcome, timeout_phase FROM node_checks WHERE node_id = ? "
                        "AND started_at >= ? AND started_at <= ? ORDER BY started_at",
                        (node_id, candidate, aggregate["started_at"]),
                    ).fetchall()
                    category = (
                        "timeout"
                        if failure_rows and all(row["outcome"] == "timeout" for row in failure_rows)
                        else "error"
                    )
                    phases = [
                        row["timeout_phase"] for row in failure_rows if row["timeout_phase"]
                    ]
                    incident_phase = (
                        max(set(phases), key=phases.count) if phases else aggregate.get("timeout_phase")
                    )
                    cursor = connection.execute(
                        "INSERT INTO incidents(node_id, started_at, confirmed_at, last_failure_at, category, "
                        "timeout_phase, failure_count, last_error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            node_id, candidate, aggregate["completed_at"], aggregate["started_at"],
                            category, incident_phase, failures,
                            aggregate.get("error_message"),
                        ),
                    )
                    current_incident_id = int(cursor.lastrowid)
                    status = "down"
                connection.execute(
                    "UPDATE node_states SET status = ?, consecutive_failures = ?, consecutive_successes = 0, "
                    "candidate_started_at = ?, recovery_started_at = NULL, current_incident_id = ?, "
                    "last_result_at = ?, last_latency_ms = NULL, last_outcome = ?, last_error = ? "
                    "WHERE node_id = ?",
                    (
                        status, failures, candidate, current_incident_id, aggregate["completed_at"],
                        aggregate["outcome"], aggregate.get("error_message"), node_id,
                    ),
                )
            else:
                current_incident_id = state["current_incident_id"]
                if current_incident_id:
                    successes = int(state["consecutive_successes"] or 0) + 1
                    recovery_started = state["recovery_started_at"] or aggregate["started_at"]
                    if successes >= recovery_threshold:
                        connection.execute(
                            "UPDATE incidents SET ended_at = ?, recovery_confirmed_at = ?, recovery_count = ?, "
                            "status = 'closed', end_confirmed = 1, close_reason = 'recovered' WHERE id = ?",
                            (recovery_started, aggregate["completed_at"], successes, current_incident_id),
                        )
                        status = "healthy"
                        current_incident_id = None
                    else:
                        status = "recovering"
                    connection.execute(
                        "UPDATE node_states SET status = ?, consecutive_failures = 0, consecutive_successes = ?, "
                        "candidate_started_at = NULL, recovery_started_at = ?, current_incident_id = ?, "
                        "last_result_at = ?, last_latency_ms = ?, last_outcome = 'success', last_error = NULL "
                        "WHERE node_id = ?",
                        (
                            status, successes, recovery_started if current_incident_id else None,
                            current_incident_id, aggregate["completed_at"], aggregate.get("latency_ms"), node_id,
                        ),
                    )
                else:
                    connection.execute(
                        "UPDATE node_states SET status = 'healthy', consecutive_failures = 0, "
                        "consecutive_successes = consecutive_successes + 1, candidate_started_at = NULL, "
                        "recovery_started_at = NULL, current_incident_id = NULL, last_result_at = ?, last_latency_ms = ?, "
                        "last_outcome = 'success', last_error = NULL WHERE node_id = ?",
                        (aggregate["completed_at"], aggregate.get("latency_ms"), node_id),
                    )

    def dashboard(self, window_seconds: int, selected_node_id: int | None, points: int = 720) -> dict[str, Any]:
        settings = self.get_settings()
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_seconds)
        now_iso = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        cutoff_iso = cutoff.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        nodes = self.list_nodes()
        if selected_node_id is None and nodes:
            selected_node_id = next((node["id"] for node in nodes if node["enabled"]), nodes[0]["id"])

        with self.connect() as connection:
            for node in nodes:
                rows = connection.execute(
                    "SELECT outcome, latency_ms FROM node_checks WHERE node_id = ? AND started_at >= ?",
                    (node["id"], cutoff_iso),
                ).fetchall()
                latencies = [float(row["latency_ms"]) for row in rows if row["latency_ms"] is not None]
                successes = sum(1 for row in rows if row["outcome"] == "success")
                timeouts = sum(1 for row in rows if row["outcome"] == "timeout")
                errors = sum(1 for row in rows if row["outcome"] == "error")
                total = len(rows)
                observed_from = max(cutoff.timestamp(), _epoch(node["created_at"]))
                expected = (
                    max(1, int((now.timestamp() - observed_from) // max(2, int(settings.get("interval_seconds", 10)))) + 1)
                    if node["enabled"]
                    else 0
                )
                node["stats"] = {
                    "checks": total,
                    "expected_checks": expected,
                    "successes": successes,
                    "timeouts": timeouts,
                    "errors": errors,
                    "availability": round(successes / total * 100, 2) if total else None,
                    "coverage": round(min(1.0, total / expected) * 100, 2) if expected else None,
                    "average_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
                    "p95_ms": _percentile(latencies, 0.95),
                }
                if not node.get("status"):
                    node["status"] = "unknown"
                if node.get("last_result_at"):
                    stale_after = max(30, int(settings.get("interval_seconds", 10)) * 3)
                    if _epoch(node["last_result_at"]) < now.timestamp() - stale_after:
                        node["status"] = "stale"

            history_rows: list[sqlite3.Row] = []
            incidents: list[dict[str, Any]] = []
            recent_failures: list[dict[str, Any]] = []
            target_results: list[dict[str, Any]] = []
            sampling_gaps: list[dict[str, Any]] = []
            if selected_node_id is not None:
                history_rows = connection.execute(
                    "SELECT started_at, outcome, latency_ms, timeout_phase, error_type FROM node_checks "
                    "WHERE node_id = ? AND started_at >= ? ORDER BY started_at",
                    (selected_node_id, cutoff_iso),
                ).fetchall()
                incidents = [
                    dict(row) for row in connection.execute(
                        "SELECT * FROM incidents WHERE node_id = ? AND started_at <= ? "
                        "AND (ended_at IS NULL OR ended_at >= ?) ORDER BY started_at",
                        (selected_node_id, now_iso, cutoff_iso),
                    ).fetchall()
                ]
                recent_failures = [
                    dict(row) for row in connection.execute(
                        "SELECT started_at, outcome, timeout_phase, error_type, error_message FROM node_checks "
                        "WHERE node_id = ? AND outcome != 'success' ORDER BY started_at DESC LIMIT 20",
                        (selected_node_id,),
                    ).fetchall()
                ]
                latest_cycle = connection.execute(
                    "SELECT cycle_id FROM node_checks WHERE node_id = ? ORDER BY id DESC LIMIT 1",
                    (selected_node_id,),
                ).fetchone()
                if latest_cycle:
                    target_results = [dict(row) for row in connection.execute(
                        "SELECT p.target, p.outcome, p.total_ms, p.tcp_ms, p.proxy_ms, p.tls_ms, p.ttfb_ms, "
                        "p.http_status, p.timeout_phase, p.error_type, p.completed_at FROM probe_results p "
                        "WHERE p.node_id = ? AND p.cycle_id = ? ORDER BY p.id",
                        (selected_node_id, latest_cycle["cycle_id"]),
                    ).fetchall()]
                selected_node = next(
                    (node for node in nodes if node["id"] == selected_node_id), None
                )
                if selected_node:
                    sampling_gaps = self._sampling_gaps(
                        history_rows,
                        max(cutoff.timestamp(), _epoch(selected_node["created_at"])),
                        now.timestamp(),
                        max(2, int(settings.get("interval_seconds", 10))),
                        bool(selected_node["enabled"]),
                    )

        return {
            "generated_at": now_iso,
            "window_started_at": cutoff_iso,
            "window_ended_at": now_iso,
            "window_seconds": window_seconds,
            "settings": settings,
            "selected_node_id": selected_node_id,
            "nodes": nodes,
            "series": self._downsample(history_rows, cutoff.timestamp(), now.timestamp(), points),
            "incidents": incidents,
            "sampling_gaps": sampling_gaps,
            "recent_failures": recent_failures,
            "target_results": target_results,
        }

    @staticmethod
    def _sampling_gaps(
        rows: Iterable[sqlite3.Row],
        observed_from_epoch: float,
        now_epoch: float,
        interval_seconds: int,
        enabled: bool,
    ) -> list[dict[str, Any]]:
        samples = list(rows)
        threshold = interval_seconds * 2.5
        gaps: list[dict[str, Any]] = []
        if not samples:
            if enabled and now_epoch - observed_from_epoch > threshold:
                gaps.append({
                    "started_at": _iso_from_epoch(observed_from_epoch),
                    "ended_at": _iso_from_epoch(now_epoch),
                    "ongoing": True,
                })
            return gaps

        first_epoch = _epoch(samples[0]["started_at"])
        if first_epoch - observed_from_epoch > threshold:
            gaps.append({
                "started_at": _iso_from_epoch(observed_from_epoch),
                "ended_at": _iso_from_epoch(first_epoch),
                "ongoing": False,
            })

        previous = first_epoch
        for row in samples[1:]:
            current = _epoch(row["started_at"])
            if current - previous > threshold:
                gaps.append({
                    "started_at": _iso_from_epoch(previous + interval_seconds),
                    "ended_at": _iso_from_epoch(current),
                    "ongoing": False,
                })
            previous = current

        if enabled and now_epoch - previous > threshold:
            gaps.append({
                "started_at": _iso_from_epoch(previous + interval_seconds),
                "ended_at": _iso_from_epoch(now_epoch),
                "ongoing": True,
            })
        return gaps

    @staticmethod
    def _downsample(
        rows: Iterable[sqlite3.Row], cutoff_epoch: float, now_epoch: float, points: int
    ) -> list[dict[str, Any]]:
        materialized = list(rows)
        if len(materialized) <= points:
            return [
                {
                    "timestamp": row["started_at"],
                    "latency_ms": row["latency_ms"],
                    "min_ms": row["latency_ms"],
                    "max_ms": row["latency_ms"],
                    "outcome": row["outcome"],
                    "timeout_count": int(row["outcome"] == "timeout"),
                    "error_count": int(row["outcome"] == "error"),
                    "sample_count": 1,
                }
                for row in materialized
            ]
        width = max(1.0, (now_epoch - cutoff_epoch) / points)
        buckets: dict[int, list[sqlite3.Row]] = {}
        for row in materialized:
            index = min(points - 1, max(0, int((_epoch(row["started_at"]) - cutoff_epoch) / width)))
            buckets.setdefault(index, []).append(row)
        result: list[dict[str, Any]] = []
        for index, bucket in sorted(buckets.items()):
            latencies = [float(row["latency_ms"]) for row in bucket if row["latency_ms"] is not None]
            timeout_count = sum(1 for row in bucket if row["outcome"] == "timeout")
            error_count = sum(1 for row in bucket if row["outcome"] == "error")
            outcome = "success" if latencies else ("timeout" if timeout_count else "error")
            result.append(
                {
                    "timestamp": _iso_from_epoch(cutoff_epoch + (index + 0.5) * width),
                    "latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
                    "min_ms": round(min(latencies), 2) if latencies else None,
                    "max_ms": round(max(latencies), 2) if latencies else None,
                    "outcome": outcome,
                    "timeout_count": timeout_count,
                    "error_count": error_count,
                    "sample_count": len(bucket),
                }
            )
        return result

    def cleanup(self, retention_days: int) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        with self.connect() as connection:
            connection.execute("DELETE FROM probe_results WHERE started_at < ?", (cutoff,))
            connection.execute("DELETE FROM node_checks WHERE started_at < ?", (cutoff,))
            connection.execute(
                "DELETE FROM incidents WHERE status = 'closed' AND ended_at < ?", (cutoff,)
            )
            connection.execute("PRAGMA optimize")
