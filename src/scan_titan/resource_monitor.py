from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any

import psutil


class ProcessTreeSampler:
    """Sample only Scan Titan and its descendant process tree."""

    def __init__(self, root_pid: int | None = None) -> None:
        self.root_pid = int(root_pid or os.getpid())
        self._tracked: dict[int, psutil.Process] = {}
        self._prime(self.root_pid)

    def _prime(self, pid: int) -> None:
        try:
            process = psutil.Process(pid)
            process.cpu_percent(interval=None)
            self._tracked[pid] = process
        except (psutil.Error, OSError):
            return

    def sample(self) -> dict[str, Any]:
        started = time.monotonic()
        try:
            root = self._tracked.get(self.root_pid) or psutil.Process(self.root_pid)
            descendants = root.children(recursive=True)
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as exc:
            return {
                "available": False,
                "root_pid": self.root_pid,
                "error": str(exc),
                "sampled_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

        processes = [root, *descendants]
        live_pids = {process.pid for process in processes}
        for pid in list(self._tracked):
            if pid not in live_pids:
                self._tracked.pop(pid, None)

        cpu_total = 0.0
        rss_total = 0
        read_total = 0
        write_total = 0
        rows: list[dict[str, Any]] = []
        for discovered in processes:
            process = self._tracked.get(discovered.pid)
            if process is None:
                process = discovered
                try:
                    process.cpu_percent(interval=None)
                except psutil.Error:
                    continue
                self._tracked[discovered.pid] = process
                cpu = 0.0
            else:
                try:
                    cpu = float(process.cpu_percent(interval=None))
                except psutil.Error:
                    continue
            try:
                memory = process.memory_info()
                rss = int(memory.rss)
                io = process.io_counters()
                read_bytes = int(getattr(io, "read_bytes", 0) or 0)
                write_bytes = int(getattr(io, "write_bytes", 0) or 0)
                name = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
            cpu_total += cpu
            rss_total += rss
            read_total += read_bytes
            write_total += write_bytes
            rows.append(
                {
                    "pid": process.pid,
                    "name": name,
                    "cpu_percent": round(cpu, 2),
                    "ram_mb": round(rss / (1024 * 1024), 2),
                }
            )

        rows.sort(key=lambda item: (float(item["cpu_percent"]), float(item["ram_mb"])), reverse=True)
        return {
            "available": True,
            "scope": "scan_titan_process_tree",
            "root_pid": self.root_pid,
            "cpu_percent": round(cpu_total, 2),
            "ram_rss_bytes": rss_total,
            "ram_mb": round(rss_total / (1024 * 1024), 2),
            "process_count": len(rows),
            "child_process_count": max(0, len(rows) - 1),
            "io_read_bytes": read_total,
            "io_write_bytes": write_total,
            "sample_duration_ms": round((time.monotonic() - started) * 1000, 2),
            "sampled_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "processes": rows[:20],
        }
