from __future__ import annotations

import statistics
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from .database import Database
from .probe import ProbeSettings, probe_proxy, utc_now


class MonitorService:
    def __init__(self, database: Database) -> None:
        self.database = database
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._node_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="node-check")
        self._probe_executor = ThreadPoolExecutor(max_workers=32, thread_name_prefix="proxy-probe")
        self._locks_guard = threading.Lock()
        self._node_locks: dict[int, threading.Lock] = {}
        self._status_guard = threading.Lock()
        self._started_at = utc_now()
        self._last_cycle_started_at: str | None = None
        self._last_cycle_completed_at: str | None = None
        self._last_cycle_error: str | None = None
        self._cycle_running = False

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._scheduler, name="monitor-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._node_executor.shutdown(wait=False, cancel_futures=True)
        self._probe_executor.shutdown(wait=False, cancel_futures=True)

    def wake(self) -> None:
        self._wake.set()

    def status(self) -> dict[str, Any]:
        with self._status_guard:
            return {
                "running": bool(self._thread and self._thread.is_alive() and not self._stop.is_set()),
                "cycle_running": self._cycle_running,
                "started_at": self._started_at,
                "last_cycle_started_at": self._last_cycle_started_at,
                "last_cycle_completed_at": self._last_cycle_completed_at,
                "last_cycle_error": self._last_cycle_error,
            }

    def _node_lock(self, node_id: int) -> threading.Lock:
        with self._locks_guard:
            return self._node_locks.setdefault(node_id, threading.Lock())

    def _scheduler(self) -> None:
        next_tick = time.monotonic()
        cleanup_day: str | None = None
        while not self._stop.is_set():
            delay = max(0.0, next_tick - time.monotonic())
            self._wake.wait(delay)
            self._wake.clear()
            if self._stop.is_set():
                break
            settings = self.database.get_settings()
            interval = max(2, int(settings.get("interval_seconds", 10)))
            try:
                self.run_all_nodes()
                today = datetime.now(timezone.utc).date().isoformat()
                if cleanup_day != today:
                    self.database.cleanup(max(1, int(settings.get("retention_days", 30))))
                    cleanup_day = today
            except Exception as error:  # Keep the scheduler alive after unexpected failures.
                with self._status_guard:
                    self._last_cycle_error = f"{type(error).__name__}: {error}"[:500]
            next_tick += interval
            now = time.monotonic()
            if next_tick < now:
                next_tick = now + interval

    def run_all_nodes(self) -> list[dict[str, Any]]:
        nodes = [node for node in self.database.list_nodes(include_secrets=True) if node["enabled"]]
        with self._status_guard:
            self._cycle_running = True
            self._last_cycle_started_at = utc_now()
            self._last_cycle_error = None
        try:
            futures = [self._node_executor.submit(self.run_node_now, int(node["id"])) for node in nodes]
            results: list[dict[str, Any]] = []
            for future in as_completed(futures):
                try:
                    value = future.result()
                    if value:
                        results.append(value)
                except Exception as error:
                    with self._status_guard:
                        self._last_cycle_error = f"{type(error).__name__}: {error}"[:500]
            return results
        finally:
            with self._status_guard:
                self._cycle_running = False
                self._last_cycle_completed_at = utc_now()

    def run_node_now(self, node_id: int) -> dict[str, Any] | None:
        lock = self._node_lock(node_id)
        if not lock.acquire(blocking=False):
            return {"node_id": node_id, "skipped": True, "reason": "probe_already_running"}
        try:
            node = self.database.get_node(node_id, include_secrets=True)
            if node is None:
                return None
            settings = self.database.get_settings()
            targets = [str(target).strip() for target in settings.get("targets", []) if str(target).strip()]
            if not targets:
                return {"node_id": node_id, "skipped": True, "reason": "no_targets"}
            probe_settings = ProbeSettings(
                connect_timeout_seconds=float(settings.get("connect_timeout_seconds", 3.0)),
                request_timeout_seconds=float(settings.get("request_timeout_seconds", 8.0)),
            )
            cycle_id = uuid.uuid4().hex
            futures = {
                self._probe_executor.submit(self._safe_probe, node, target, probe_settings): index
                for index, target in enumerate(targets)
            }
            indexed_results: list[tuple[int, dict[str, Any]]] = []
            for future in as_completed(futures):
                indexed_results.append((futures[future], future.result()))
            results = [result for _, result in sorted(indexed_results)]
            aggregate = self._aggregate(results)
            self.database.record_cycle(
                node_id=node_id,
                cycle_id=cycle_id,
                results=results,
                aggregate=aggregate,
                failure_threshold=max(1, int(settings.get("failure_threshold", 3))),
                recovery_threshold=max(1, int(settings.get("recovery_threshold", 2))),
                interval_seconds=max(2, int(settings.get("interval_seconds", 10))),
            )
            return {"node_id": node_id, "cycle_id": cycle_id, "aggregate": aggregate, "results": results}
        finally:
            lock.release()

    @staticmethod
    def _safe_probe(
        node: dict[str, Any], target: str, settings: ProbeSettings
    ) -> dict[str, Any]:
        try:
            return probe_proxy(node, target, settings)
        except Exception as error:
            timestamp = utc_now()
            return {
                "target": target,
                "started_at": timestamp,
                "completed_at": timestamp,
                "outcome": "error",
                "timeout_phase": None,
                "tcp_ms": None,
                "proxy_ms": None,
                "tls_ms": None,
                "ttfb_ms": None,
                "total_ms": 0.0,
                "http_status": None,
                "error_type": "internal_error",
                "error_message": f"{type(error).__name__}: {error}"[:500],
            }

    @staticmethod
    def _aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
        started_at = min(result["started_at"] for result in results)
        completed_at = max(result["completed_at"] for result in results)
        successes = [result for result in results if result["outcome"] == "success"]
        if successes:
            # Keep the latency series tied to the primary target. A fallback can
            # prove reachability, but mixing its route into the primary P95 would
            # make the graph change meaning whenever one target is unavailable.
            primary = results[0]
            latency = (
                float(primary["total_ms"])
                if primary["outcome"] == "success" and primary.get("total_ms") is not None
                else None
            )
            return {
                "started_at": started_at,
                "completed_at": completed_at,
                "outcome": "success",
                "latency_ms": round(latency, 2) if latency is not None else None,
                "timeout_phase": None,
                "error_type": "partial_target_failure" if len(successes) != len(results) else None,
                "error_message": (
                    f"{len(results) - len(successes)} of {len(results)} targets failed"
                    if len(successes) != len(results)
                    else None
                ),
            }

        timeouts = [result for result in results if result["outcome"] == "timeout"]
        if len(timeouts) == len(results):
            phases = [result.get("timeout_phase") for result in timeouts if result.get("timeout_phase")]
            dominant_phase = Counter(phases).most_common(1)[0][0] if phases else "total"
            waited = [float(result.get("total_ms") or 0) for result in timeouts]
            return {
                "started_at": started_at,
                "completed_at": completed_at,
                "outcome": "timeout",
                "latency_ms": None,
                "timeout_phase": dominant_phase,
                "error_type": "timeout",
                "error_message": f"all {len(results)} targets timed out; median wait {statistics.median(waited):.0f} ms",
            }

        representative = next((result for result in results if result["outcome"] == "error"), results[0])
        return {
            "started_at": started_at,
            "completed_at": completed_at,
            "outcome": "error",
            "latency_ms": None,
            "timeout_phase": representative.get("timeout_phase"),
            "error_type": representative.get("error_type") or "probe_error",
            "error_message": representative.get("error_message") or "all targets failed",
        }
