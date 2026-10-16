"""Bounded, session-aware chart history built only from observed telemetry."""
from __future__ import annotations

import math
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any


def monitor_base_dir(script_file: Path) -> Path:
    """Resolve both src/scan_titan and older standalone monitor layouts."""
    folder = script_file.resolve().parent
    if folder.name == "scan_titan" and folder.parent.name == "src":
        return folder.parent.parent
    return folder


def number(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return max(0.0, result) if math.isfinite(result) else default
    except (TypeError, ValueError, OverflowError):
        return default


def timestamp(value: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


class TelemetryHistory:
    """Deduplicate producer timestamps; never turn UI refreshes into samples.

    HTTP counters belong to the current target/module. A context change, counter
    reset, or long gap starts a new baseline instead of creating a rate spike.
    CPU is process-tree percent and may exceed 100 on multicore systems.
    """

    def __init__(self, limit: int = 120) -> None:
        self.series: dict[str, deque[tuple[float, float | None]]] = {
            key: deque(maxlen=limit) for key in ("cpu", "ram", "requests", "progress")
        }
        self.session: tuple[Any, ...] | None = None
        self._http_previous: tuple[Any, ...] | None = None
        self.rate: float | None = None

    def clear(self) -> None:
        for points in self.series.values():
            points.clear()
        self.session = None
        self._http_previous = None
        self.rate = None

    def _append(self, key: str, stamp: float, value: float | None) -> bool:
        points = self.series[key]
        if points and stamp <= points[-1][0]:
            return False
        points.append((stamp, value))
        return True

    def ingest(self, data: dict[str, Any], source: str, *, stale: bool = False) -> None:
        session = (source, data.get("started_at"), data.get("pid"))
        if session != self.session:
            self.clear()
            self.session = session
        if stale:
            self.rate = None
            self._http_previous = None
            return
        stamp = timestamp(data.get("updated_at"))
        if stamp is None:
            return
        self._append("progress", stamp, min(100.0, number(data.get("global_percent"))))

        resources = data.get("resources") or {}
        resource_stamp = timestamp(resources.get("sampled_at")) or stamp
        if resources.get("available") and abs(stamp - resource_stamp) <= 60:
            self._append("cpu", resource_stamp, number(resources.get("cpu_percent")))
            self._append("ram", resource_stamp, number(resources.get("ram_mb")))
        else:
            self._append("cpu", resource_stamp, None)
            self._append("ram", resource_stamp, None)

        activity = data.get("http_activity")
        if not isinstance(activity, dict) or "completed" not in activity or data.get("status") != "running":
            self.rate = None
            self._http_previous = None
            self._append("requests", stamp, None)
            return
        count = number(activity.get("completed"))
        context = (data.get("current_target"), data.get("current_module"))
        previous = self._http_previous
        if previous and stamp <= previous[0]:
            return
        self.rate = None
        if previous:
            delta = stamp - previous[0]
            if context == previous[2] and count >= previous[1] and 0 < delta <= 60:
                self.rate = (count - previous[1]) / delta
        self._http_previous = (stamp, count, context)
        self._append("requests", stamp, self.rate)
