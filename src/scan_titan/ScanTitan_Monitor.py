# -*- coding: utf-8 -*-
r"""
Scan Titan Monitor

Read-only GUI monitor for Scan Titan runtime telemetry. Run it from any Scan
Titan folder while Main.py is scanning:

    python main.py --monitor

Or point it to another scan copy:

    python main.py --monitor --path C:\Audits\ScanCopy
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import customtkinter as ctk

from monitor_model import monitor_base_dir
from monitor_ui import DashboardUI

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except Exception as exc:  # pragma: no cover - import guard for broken Tcl setups
    raise RuntimeError(f"Tkinter is required to run the monitor: {exc}") from exc


APP_TITLE = "Scan Titan Monitor"
RUNTIME_NAME = "scan_titan_runtime.json"
REFRESH_MS = 1500
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
DEFAULT_BASE_DIR = Path(os.environ.get("SCAN_TITAN_BASE_DIR", monitor_base_dir(Path(__file__)))).resolve()


def resolve_reports_dir(base_dir: Path) -> Path:
    base_dir = base_dir.resolve()
    same_scan = base_dir == Path(os.environ.get("SCAN_TITAN_BASE_DIR", DEFAULT_BASE_DIR)).resolve()
    configured = os.environ.get("SCAN_TITAN_RUNTIME_FILE", "") if same_scan else ""
    if configured and Path(configured).is_file():
        return Path(configured).resolve().parent
    output = os.environ.get("SCAN_TITAN_REPORTS_DIR", "") if same_scan else ""
    candidates = list(dict.fromkeys(
        ([Path(output).resolve()] if output else [])
        + [base_dir / "audit_reports", base_dir / "reports"]
    ))
    available = [path for path in candidates if (path / RUNTIME_NAME).is_file()]
    if available:
        return max(available, key=lambda path: (path / RUNTIME_NAME).stat().st_mtime)
    return next((path for path in candidates if path.exists()), candidates[0])


def resolve_runtime_file(base_dir: Path) -> Path:
    configured = os.environ.get("SCAN_TITAN_RUNTIME_FILE", "")
    same_scan = base_dir.resolve() == Path(os.environ.get("SCAN_TITAN_BASE_DIR", DEFAULT_BASE_DIR)).resolve()
    if same_scan and configured and Path(configured).is_file():
        return Path(configured).resolve()
    return resolve_reports_dir(base_dir) / RUNTIME_NAME


def runtime_is_stale(data: dict[str, Any], max_age: float = 60.0) -> bool:
    if data.get("status") not in {"running", "finishing"}:
        return False
    updated = parse_timestamp(data.get("updated_at"))
    return updated is None or (datetime.now() - updated).total_seconds() > max_age


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=APP_TITLE,
        description="Read-only GUI monitor for Scan Titan runtime telemetry.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--path",
        default=str(DEFAULT_BASE_DIR),
        help="Scan Titan folder to monitor",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run a non-GUI smoke test and exit",
    )
    return parser.parse_args()


def safe_text(value: Any, limit: int = 140) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    if len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def read_json(path: Path) -> dict[str, Any]:
    try:
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def read_jsonl_tail(path: Path, limit: int = 80) -> list[dict[str, Any]]:
    try:
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    records: list[dict[str, Any]] = []
    for line in lines[-max(1, limit):]:
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def format_seconds(value: Any) -> str:
    try:
        seconds = int(float(value or 0))
    except Exception:
        seconds = 0
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


def parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except ValueError:
            continue
    return None


def update_age_text(value: Any) -> str:
    parsed = parse_timestamp(value)
    if not parsed:
        return "sin lectura"
    age = max(0, int((datetime.now() - parsed).total_seconds()))
    return f"hace {format_seconds(age)}"


def open_path(path: Path) -> None:
    try:
        if not path.exists():
            messagebox.showwarning(APP_TITLE, f"No existe:\n{path}")
            return
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception as exc:
        messagebox.showerror(APP_TITLE, f"No se pudo abrir:\n{path}\n\n{exc}")


class MonitorApp(DashboardUI, ctk.CTk):
    def __init__(self, base_dir: Path) -> None:
        super().__init__()
        self.base_dir = base_dir.resolve()
        self.reports_dir = resolve_reports_dir(self.base_dir)
        self.runtime_file = resolve_runtime_file(self.base_dir)
        self._refresh_job: str | None = None
        self.title(APP_TITLE)
        # Tk reports logical screen dimensions here; CTk scales geometry itself.
        width = min(1480, max(560, self.winfo_screenwidth() - 40))
        height = min(940, max(560, self.winfo_screenheight() - 60))
        self.geometry(f"{width}x{height}")
        self.minsize(560, 520)
        self._setup_style()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.refresh()

    def destroy(self) -> None:
        for name in ("_refresh_job", "_layout_job"):
            job = getattr(self, name, None)
            if job:
                self.after_cancel(job)
                setattr(self, name, None)
        super().destroy()

    def choose_folder(self) -> None:
        chosen = filedialog.askdirectory(initialdir=str(self.base_dir), title="Selecciona carpeta de Scan Titan")
        if not chosen:
            return
        self.base_dir = Path(chosen).resolve()
        self.reports_dir = resolve_reports_dir(self.base_dir)
        self.runtime_file = resolve_runtime_file(self.base_dir)
        self.path_var.set(str(self.base_dir))
        self.history.clear()
        self.refresh()

    def open_dashboard(self) -> None:
        candidates = [
            self.base_dir / "Daily_vulns_report.html",
            self.reports_dir / "Daily_vulns_report.html",
            self.reports_dir / "External_Tools_Observability.html",
        ]
        for candidate in candidates:
            if candidate.exists():
                open_path(candidate)
                return
        messagebox.showwarning(APP_TITLE, "No encontre dashboard HTML en esta carpeta.")

    def refresh(self) -> None:
        if self._refresh_job is not None:
            self.after_cancel(self._refresh_job)
            self._refresh_job = None
        self.runtime_file = resolve_runtime_file(self.base_dir)
        self.reports_dir = self.runtime_file.parent
        data = read_json(self.runtime_file)
        if not data:
            self._render_fallback()
        else:
            self._render_runtime(data)
        self._refresh_job = self.after(REFRESH_MS, self.refresh)

    def _render_fallback(self) -> None:
        state_file = self.reports_dir / "scan_titan_state.json"
        state = read_json(state_file)
        latest_report = self._latest_target_report()
        report_data = read_json(latest_report) if latest_report else {}
        external_rows = self._external_rows_from_observability()
        finding_rows = self._finding_rows_from_report(report_data)
        event_rows = [
            (
                "",
                "WARN",
                (
                    f"No existe {RUNTIME_NAME}. Si Main.py ya estaba corriendo antes de la actualizacion, "
                    "esa corrida no puede emitir telemetria viva; reinicia Main.py para ver porcentaje real."
                ),
            )
        ]
        if latest_report:
            event_rows.append(("", "INFO", f"Fallback cargado desde ultimo reporte: {latest_report.name}"))
        if external_rows:
            event_rows.append(("", "INFO", "Fallback cargado desde external_tools_observability.jsonl"))

        self._set_status("REPORTES" if latest_report or external_rows or state else "ESPERANDO", "#f39c12" if latest_report or external_rows or state else "#43505c")
        self.global_bar.set(0)
        self.module_bar.set(0)
        self.global_text.configure(text="100.00%" if latest_report else "0.00%")
        self.module_text.configure(text="0.00%")
        self.metric_vars["target"].set(safe_text(report_data.get("target") or "-", 90))
        self.metric_vars["phase"].set("fallback report/log")
        self.metric_vars["module"].set("sin runtime vivo")
        self.metric_vars["tests"].set("-")
        elapsed_source = report_data.get("date") or (
            datetime.fromtimestamp(latest_report.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            if latest_report
            else ""
        )
        self.metric_vars["elapsed"].set(update_age_text(elapsed_source))
        self.metric_vars["cpu"].set("-")
        self.metric_vars["ram"].set("-")
        self.metric_vars["processes"].set("-")
        if isinstance(report_data.get("summary"), dict):
            counts = report_data.get("summary", {})
        elif state:
            counts = self._counts_from_state(state)
        else:
            counts = {}
        self.metric_vars["findings"].set(self._format_counts(counts))
        self._replace_rows(
            self.modules_tree,
            self._module_rows_from_report(report_data, latest_report),
        )
        self._replace_rows(self.external_tree, external_rows)
        self._replace_rows(self.findings_tree, finding_rows)
        self._replace_rows(self.events_tree, event_rows)
        self._replace_rows(self.resources_tree, [])
        if latest_report or external_rows or state:
            self.footer_var.set(
                f"Modo fallback activo | Runtime ausente: {self.runtime_file} | "
                "reinicia Main.py para telemetria viva"
            )
        else:
            self.footer_var.set(f"Esperando {self.runtime_file}")

        self._update_dashboard({
            "current_target": report_data.get("target"),
            "current_phase": "Reportes anteriores",
            "findings": counts,
            "finding_unique": report_data.get("total_findings"),
        }, fallback=True)

    def _render_runtime(self, data: dict[str, Any]) -> None:
        status = safe_text(data.get("status") or "unknown").upper()
        stale = runtime_is_stale(data)
        self._set_status("SIN ACTUALIZAR" if stale else status, "#f39c12" if stale else self._status_color(status.lower()))
        global_percent = self._float_value(data.get("global_percent"))
        module_percent = self._float_value(data.get("module_percent"))
        self.global_bar.set(global_percent / 100)
        self.module_bar.set(module_percent / 100)
        self.global_text.configure(text=f"{global_percent:.2f}%")
        self.module_text.configure(text=f"{module_percent:.2f}%")
        if stale:
            self.global_text.configure(text="Ultimo dato")
            self.module_text.configure(text="Sin datos recientes")

        target = safe_text(data.get("current_target") or "-", 90)
        phase = safe_text(data.get("current_phase") or "-", 90)
        module = safe_text(data.get("current_module") or "-", 90)
        tested = int(data.get("module_tested") or 0)
        total = int(data.get("module_total") or 0)
        hits = int(data.get("module_hits") or 0)
        target_index = int(data.get("target_index") or 0)
        target_total = int(data.get("target_total") or 0)
        self.metric_vars["target"].set(f"{target_index}/{target_total} {target}")
        self.metric_vars["phase"].set(phase)
        self.metric_vars["module"].set(module)
        self.metric_vars["tests"].set(f"{tested}/{total or '-'} | hits={hits}")
        counts_text = self._format_counts(data.get("findings", {}))
        unique_count = int(data.get("finding_unique") or sum(int(v or 0) for v in (data.get("findings") or {}).values()))
        occurrence_count = int(data.get("finding_occurrences") or unique_count)
        self.metric_vars["findings"].set(f"{counts_text}\nU:{unique_count} | O:{occurrence_count}")
        started = parse_timestamp(data.get("started_at"))
        elapsed = data.get("elapsed_seconds")
        if started and not stale and data.get("status") in {"running", "paused", "finishing"}:
            elapsed = (datetime.now() - started).total_seconds()
        self.metric_vars["elapsed"].set(format_seconds(elapsed))
        resources = data.get("resources") if isinstance(data.get("resources"), dict) else {}
        peaks = data.get("resource_peaks") if isinstance(data.get("resource_peaks"), dict) else {}
        if resources.get("available"):
            self.metric_vars["cpu"].set(
                f"{float(resources.get('cpu_percent') or 0.0):.1f}%\nPico {float(peaks.get('cpu_percent') or 0.0):.1f}%"
            )
            self.metric_vars["ram"].set(
                f"{float(resources.get('ram_mb') or 0.0):.1f} MB\nPico {float(peaks.get('ram_mb') or 0.0):.1f} MB"
            )
            self.metric_vars["processes"].set(
                f"{int(resources.get('process_count') or 0)} total\n{int(resources.get('child_process_count') or 0)} hijos"
            )
        else:
            detail = safe_text(resources.get("error") or "sin muestra", 80)
            self.metric_vars["cpu"].set("N/D")
            self.metric_vars["ram"].set("N/D")
            self.metric_vars["processes"].set(detail)

        self._replace_rows(
            self.modules_tree,
            [
                (
                    safe_text(item.get("target"), 90),
                    safe_text(item.get("module"), 90),
                    safe_text(item.get("status"), 40),
                    str(item.get("tested", "")),
                    str(item.get("hits", "")),
                    str(item.get("findings", "")),
                    format_seconds(item.get("duration_seconds")),
                    safe_text(item.get("error"), 220),
                )
                for item in data.get("modules", []) or []
                if isinstance(item, dict)
            ],
        )
        self._replace_rows(
            self.external_tree,
            [
                (
                    safe_text(item.get("tool"), 50),
                    safe_text(item.get("profile"), 100),
                    safe_text(item.get("status"), 40),
                    str(item.get("returncode", "")),
                    str(item.get("findings", "")),
                    format_seconds(item.get("duration_seconds")),
                    str(bool(item.get("timed_out"))),
                    safe_text(item.get("error"), 240),
                )
                for item in data.get("external_tools", []) or []
                if isinstance(item, dict)
            ],
        )
        self._replace_rows(
            self.findings_tree,
            [
                (
                    safe_text(item.get("time"), 40),
                    safe_text(item.get("severity"), 20),
                    safe_text(item.get("target"), 90),
                    safe_text(item.get("title"), 220),
                    safe_text(item.get("source"), 80),
                    safe_text(item.get("fingerprint"), 32),
                )
                for item in data.get("recent_findings", []) or []
                if isinstance(item, dict)
            ],
        )
        self._replace_rows(
            self.events_tree,
            [
                (
                    safe_text(item.get("time"), 40),
                    safe_text(item.get("level"), 30),
                    safe_text(item.get("message"), 680),
                )
                for item in data.get("events", []) or []
                if isinstance(item, dict)
            ],
        )
        self._replace_rows(
            self.resources_tree,
            [
                (
                    str(item.get("pid", "")),
                    safe_text(item.get("name"), 120),
                    f"{float(item.get('cpu_percent') or 0.0):.1f}",
                    f"{float(item.get('ram_mb') or 0.0):.1f}",
                )
                for item in resources.get("processes", []) or []
                if isinstance(item, dict)
            ],
        )
        updated = data.get("updated_at") or ""
        last_error = safe_text(data.get("last_error") or "", 240)
        last_warning = safe_text(data.get("last_warning") or "", 240)
        footer = f"Actualizado {update_age_text(updated)} | Runtime: {self.runtime_file}"
        if stale:
            footer += " | Telemetria antigua: no confirma avance del proceso"
        elif data.get("current_detail"):
            footer += f" | {safe_text(data['current_detail'], 220)}"
        if last_error:
            footer += f" | Ultimo error: {last_error}"
        elif last_warning:
            footer += f" | Ultimo aviso: {last_warning}"
        self.footer_var.set(footer)
        self._update_dashboard(data, stale=stale)

    def _set_status(self, text: str, color: str) -> None:
        labels = {
            "RUNNING": "EN VIVO", "FINISHING": "FINALIZANDO", "PAUSED": "PAUSADO",
            "FINISHED": "FINALIZADO", "FINISHED_EARLY": "FINALIZADO PARCIAL",
            "NO_TARGETS": "SIN OBJETIVOS", "FAILED": "ERROR", "INTERRUPTED": "INTERRUMPIDO",
            "CANCELLED": "CANCELADO", "UNKNOWN": "SIN ESTADO",
        }
        self.status_label.configure(text=labels.get(text, text), text_color=color, fg_color="#1b283d")

    def _status_color(self, status: str) -> str:
        if status in {"running", "scan", "module", "external"}:
            return "#00a3d7"
        if status in {"paused", "finishing"}:
            return "#f39c12"
        if status in {"failed", "timeout", "interrupted", "cancelled"}:
            return "#d63031"
        if status in {"finished", "finished_early", "no_targets"}:
            return "#00b894"
        return "#43505c"

    def _replace_rows(self, tree: ttk.Treeview, rows: list[tuple[Any, ...]]) -> None:
        normalized = tuple(tuple("" if item is None else item for item in row) for row in rows)
        if self._rows_cache.get(tree) == normalized:
            return
        self._rows_cache[tree] = normalized
        selected = [tree.item(iid, "values") for iid in tree.selection()]
        x_position, y_position = tree.xview()[0], tree.yview()[0]
        tree.delete(*tree.get_children())
        for index, values in enumerate(normalized):
            tags = ["alternate"] if index % 2 else []
            for value in values:
                label = str(value)
                if label in SEVERITIES or label in {"running", "finished", "degraded", "failed", "timeout"}:
                    tags.append(label)
            iid = tree.insert("", "end", values=values, tags=tuple(tags))
            if tuple(str(v) for v in values) in selected:
                tree.selection_set(iid)
                tree.focus(iid)
        tree.xview_moveto(x_position)
        tree.yview_moveto(y_position)

    def _latest_target_report(self) -> Path | None:
        if not self.reports_dir.exists():
            return None
        candidates: list[Path] = []
        for path in self.reports_dir.glob("*.json"):
            name = path.name.lower()
            if name.startswith(("nuclei_out_", "zap_alerts_", "ffuf_out_")):
                continue
            if name in {
                "scan_titan_state.json",
                "scan_titan_runtime.json",
                "tool_inventory.json",
            }:
                continue
            data = read_json(path)
            if data.get("schema") == "scan_titan_target_report_v1" or isinstance(data.get("findings"), list):
                candidates.append(path)
        if not candidates:
            return None
        return max(candidates, key=lambda item: item.stat().st_mtime)

    def _module_rows_from_report(self, data: dict[str, Any], report_path: Path | None) -> list[tuple[Any, ...]]:
        if not data:
            return []
        target = data.get("target") or data.get("url") or "-"
        total = data.get("total_findings") or len(data.get("findings", []) or [])
        date = data.get("date") or (datetime.fromtimestamp(report_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S") if report_path else "")
        return [
            (
                safe_text(target, 90),
                "target_report",
                "finished",
                "-",
                "-",
                str(total),
                safe_text(date, 90),
                "Reporte previo cargado por fallback; no es progreso vivo.",
            )
        ]

    def _finding_rows_from_report(self, data: dict[str, Any]) -> list[tuple[Any, ...]]:
        rows: list[tuple[Any, ...]] = []
        date = data.get("date") or ""
        findings = data.get("findings") if isinstance(data.get("findings"), list) else []
        for item in findings[:80]:
            if not isinstance(item, dict):
                continue
            rows.append(
                (
                    safe_text(item.get("last_seen") or item.get("first_seen") or date, 40),
                    safe_text(item.get("severity"), 20),
                    safe_text(item.get("target") or data.get("target"), 90),
                    safe_text(item.get("title"), 220),
                    safe_text(item.get("source"), 80),
                    safe_text(item.get("fingerprint"), 32),
                )
            )
        return rows

    def _external_rows_from_observability(self) -> list[tuple[Any, ...]]:
        records = read_jsonl_tail(self.reports_dir / "external_tools_observability.jsonl", limit=120)
        rows: list[tuple[Any, ...]] = []
        for item in reversed(records[-80:]):
            if item.get("timed_out"):
                status = "timeout"
            elif item.get("returncode") not in {0, None, ""}:
                status = "degraded" if int(item.get("parsed_findings") or 0) > 0 else "failed"
            else:
                status = "finished"
            rows.append(
                (
                    safe_text(item.get("tool"), 50),
                    safe_text(item.get("profile"), 100),
                    status,
                    str(item.get("returncode", "")),
                    str(item.get("parsed_findings", "")),
                    format_seconds(item.get("duration_seconds")),
                    str(bool(item.get("timed_out"))),
                    safe_text(item.get("empty_reason") or item.get("stderr_summary"), 240),
                )
            )
        return rows

    def _counts_from_state(self, state: dict[str, Any]) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITIES}
        candidates: list[Any] = []
        for key in ("vulnerabilities", "findings", "records", "items"):
            value = state.get(key)
            if isinstance(value, list):
                candidates.extend(value)
            elif isinstance(value, dict):
                candidates.extend(value.values())
        for item in candidates:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or item.get("state") or "active").lower()
            if status and status not in {"active", "open", "vigente", "new"}:
                continue
            severity = safe_text(item.get("severity") or item.get("sev") or "Info", 20).title()
            if severity not in counts:
                severity = "Info"
            counts[severity] += 1
        return counts

    def _format_counts(self, counts: Any) -> str:
        if not isinstance(counts, dict):
            counts = {}
        parts = []
        for severity in SEVERITIES:
            value = int(counts.get(severity, 0) or 0)
            short = {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Info": "I"}[severity]
            parts.append(f"{short}:{value}")
        return " ".join(parts)

    def _float_value(self, value: Any) -> float:
        try:
            return max(0.0, min(100.0, float(value or 0)))
        except Exception:
            return 0.0


def run_self_test() -> int:
    from monitor_model import TelemetryHistory

    sample = {
        "status": "running",
        "global_percent": 51.5,
        "module_percent": 25,
        "findings": {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5},
        "modules": [{"module": "headers", "status": "running"}],
        "external_tools": [{"tool": "nmap", "profile": "service_top_1000", "status": "finished"}],
        "recent_findings": [{"severity": "High", "title": "demo"}],
        "events": [{"level": "INFO", "message": "demo"}],
        "resources": {"available": True, "cpu_percent": 12.5, "ram_mb": 256.0, "process_count": 3},
    }
    assert abs(float(sample["global_percent"]) - 51.5) < 0.01
    assert sample["findings"]["High"] == 2
    assert format_seconds(3661) == "1h 01m 01s"
    assert safe_text("a\nb") == "a b"
    assert sample["resources"]["process_count"] == 3
    sample.update(pid=1, started_at="2026-10-16T12:00:00", updated_at="2026-10-16T12:00:00",
                  current_target="example.test", current_module="headers", http_activity={"completed": 100})
    history = TelemetryHistory()
    history.ingest(sample, "self-test")
    history.ingest(sample, "self-test")
    assert len(history.series["cpu"]) == 1
    sample.update(updated_at="2026-10-16T12:00:10", http_activity={"completed": 150})
    history.ingest(sample, "self-test")
    assert history.rate == 5.0
    history.ingest(sample, "self-test", stale=True)
    assert history.rate is None
    print("SCAN_TITAN_MONITOR_SELFTEST_OK")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()
    app = MonitorApp(Path(args.path))
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
