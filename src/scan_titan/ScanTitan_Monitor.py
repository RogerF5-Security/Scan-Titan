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

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except Exception as exc:  # pragma: no cover - import guard for broken Tcl setups
    raise RuntimeError(f"Tkinter is required to run the monitor: {exc}") from exc


APP_TITLE = "Scan Titan Monitor"
RUNTIME_NAME = "scan_titan_runtime.json"
REFRESH_MS = 1500
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
DEFAULT_BASE_DIR = Path(os.environ.get("SCAN_TITAN_BASE_DIR", Path(__file__).resolve().parents[2])).resolve()


def resolve_reports_dir(base_dir: Path) -> Path:
    reports = base_dir / "reports"
    legacy = base_dir / "audit_reports"
    if reports.exists() or not legacy.exists():
        return reports
    return legacy


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
        return json.loads(path.read_text(encoding="utf-8"))
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


class MonitorApp(tk.Tk):
    def __init__(self, base_dir: Path) -> None:
        super().__init__()
        self.base_dir = base_dir.resolve()
        self.reports_dir = resolve_reports_dir(self.base_dir)
        self.runtime_file = self.reports_dir / RUNTIME_NAME
        self.title(APP_TITLE)
        self.geometry("1240x820")
        self.minsize(1080, 680)
        self.configure(bg="#101820")
        self._setup_style()
        self._build_ui()
        self.refresh()

    def _setup_style(self) -> None:
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        self.style.configure("TFrame", background="#101820")
        self.style.configure("Panel.TFrame", background="#16232e", relief="flat")
        self.style.configure("TLabel", background="#101820", foreground="#e7eef7")
        self.style.configure("Panel.TLabel", background="#16232e", foreground="#e7eef7")
        self.style.configure("Muted.TLabel", background="#101820", foreground="#9fb0c2")
        self.style.configure("Title.TLabel", background="#101820", foreground="#ffffff", font=("Segoe UI", 20, "bold"))
        self.style.configure("Metric.TLabel", background="#16232e", foreground="#ffffff", font=("Segoe UI", 18, "bold"))
        self.style.configure("Accent.Horizontal.TProgressbar", troughcolor="#22313f", background="#00b7ff")
        self.style.configure("Danger.Horizontal.TProgressbar", troughcolor="#22313f", background="#ff4d5e")
        self.style.configure("Treeview", background="#0f1720", foreground="#e7eef7", fieldbackground="#0f1720", rowheight=26)
        self.style.configure("Treeview.Heading", background="#263746", foreground="#ffffff", font=("Segoe UI", 9, "bold"))
        self.style.map("Treeview", background=[("selected", "#275f7c")])
        self.style.configure("TNotebook", background="#101820", borderwidth=0)
        self.style.configure("TNotebook.Tab", background="#263746", foreground="#ffffff", padding=(14, 8))
        self.style.map("TNotebook.Tab", background=[("selected", "#00a3d7")])

    def _build_ui(self) -> None:
        container = ttk.Frame(self, padding=16)
        container.pack(fill="both", expand=True)

        header = ttk.Frame(container)
        header.pack(fill="x")
        ttk.Label(header, text="SCAN TITAN :: LIVE OPERATIONS MONITOR", style="Title.TLabel").pack(side="left")
        self.status_label = tk.Label(
            header,
            text="IDLE",
            bg="#43505c",
            fg="#ffffff",
            font=("Segoe UI", 11, "bold"),
            padx=14,
            pady=6,
        )
        self.status_label.pack(side="right")

        path_row = ttk.Frame(container)
        path_row.pack(fill="x", pady=(10, 12))
        self.path_var = tk.StringVar(value=str(self.base_dir))
        ttk.Label(path_row, textvariable=self.path_var, style="Muted.TLabel").pack(side="left", fill="x", expand=True)
        self._button(path_row, "Refresh", self.refresh).pack(side="right", padx=(8, 0))
        self._button(path_row, "Cambiar carpeta", self.choose_folder).pack(side="right", padx=(8, 0))

        progress = ttk.Frame(container)
        progress.pack(fill="x", pady=(0, 12))
        ttk.Label(progress, text="Progreso global").grid(row=0, column=0, sticky="w")
        self.global_bar = ttk.Progressbar(progress, style="Accent.Horizontal.TProgressbar", maximum=100)
        self.global_bar.grid(row=1, column=0, sticky="ew", padx=(0, 12))
        self.global_text = ttk.Label(progress, text="0.00%", style="Muted.TLabel")
        self.global_text.grid(row=1, column=1, sticky="e")
        ttk.Label(progress, text="Modulo actual").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.module_bar = ttk.Progressbar(progress, style="Danger.Horizontal.TProgressbar", maximum=100)
        self.module_bar.grid(row=3, column=0, sticky="ew", padx=(0, 12))
        self.module_text = ttk.Label(progress, text="0.00%", style="Muted.TLabel")
        self.module_text.grid(row=3, column=1, sticky="e")
        progress.columnconfigure(0, weight=1)

        cards = ttk.Frame(container)
        cards.pack(fill="x", pady=(0, 12))
        self.metric_vars = {
            "target": tk.StringVar(value="-"),
            "phase": tk.StringVar(value="-"),
            "module": tk.StringVar(value="-"),
            "tests": tk.StringVar(value="-"),
            "findings": tk.StringVar(value="-"),
            "elapsed": tk.StringVar(value="-"),
        }
        self._metric_card(cards, "Target", self.metric_vars["target"]).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._metric_card(cards, "Fase", self.metric_vars["phase"]).grid(row=0, column=1, sticky="ew", padx=8)
        self._metric_card(cards, "Modulo", self.metric_vars["module"]).grid(row=0, column=2, sticky="ew", padx=8)
        self._metric_card(cards, "Pruebas / Hits", self.metric_vars["tests"]).grid(row=0, column=3, sticky="ew", padx=8)
        self._metric_card(cards, "Vulns unicas / ocurrencias", self.metric_vars["findings"]).grid(row=0, column=4, sticky="ew", padx=8)
        self._metric_card(cards, "Tiempo", self.metric_vars["elapsed"]).grid(row=0, column=5, sticky="ew", padx=(8, 0))
        for index in range(6):
            cards.columnconfigure(index, weight=1, uniform="cards")

        actions = ttk.Frame(container)
        actions.pack(fill="x", pady=(0, 12))
        self._button(actions, "Abrir reports", lambda: open_path(self.reports_dir)).pack(side="left", padx=(0, 8))
        self._button(actions, "Abrir Dashboard HTML", self.open_dashboard).pack(side="left", padx=(0, 8))
        self._button(actions, "Abrir Recon Matrix", lambda: open_path(self.reports_dir / "Recon_Matrix.xlsx")).pack(side="left", padx=(0, 8))
        self._button(actions, "Abrir Runtime JSON", lambda: open_path(self.runtime_file)).pack(side="left", padx=(0, 8))

        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill="both", expand=True)

        self.modules_tree = self._tree(
            "Fases / Modulos",
            ("target", "module", "status", "tested", "hits", "findings", "duration", "error"),
            ("Target", "Modulo", "Estado", "Tested", "Hits", "Findings", "Tiempo", "Error"),
        )
        self.external_tree = self._tree(
            "Herramientas externas",
            ("tool", "profile", "status", "rc", "findings", "duration", "timeout", "error"),
            ("Tool", "Perfil", "Estado", "RC", "Parsed", "Tiempo", "Timeout", "Error"),
        )
        self.findings_tree = self._tree(
            "Hallazgos recientes",
            ("time", "severity", "target", "title", "source", "fingerprint"),
            ("Hora", "Sev", "Target", "Titulo", "Source", "Fingerprint"),
        )
        self.events_tree = self._tree(
            "Eventos",
            ("time", "level", "message"),
            ("Hora", "Nivel", "Mensaje"),
        )
        for tree in (self.modules_tree, self.external_tree, self.findings_tree, self.events_tree):
            self._configure_columns(tree)

        self.footer_var = tk.StringVar(value="Esperando telemetria...")
        ttk.Label(container, textvariable=self.footer_var, style="Muted.TLabel").pack(fill="x", pady=(10, 0))

    def _button(self, parent: tk.Widget, text: str, command: Any) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg="#00a3d7",
            fg="#ffffff",
            activebackground="#02b8f3",
            activeforeground="#ffffff",
            relief="flat",
            padx=12,
            pady=6,
            font=("Segoe UI", 9, "bold"),
        )

    def _metric_card(self, parent: tk.Widget, label: str, variable: tk.StringVar) -> ttk.Frame:
        frame = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        ttk.Label(frame, text=label, style="Panel.TLabel").pack(anchor="w")
        ttk.Label(frame, textvariable=variable, style="Metric.TLabel", wraplength=180).pack(anchor="w", pady=(6, 0))
        return frame

    def _tree(self, tab_name: str, columns: tuple[str, ...], headings: tuple[str, ...]) -> ttk.Treeview:
        frame = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(frame, text=tab_name)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        scroll_y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        scroll_x = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        for column, heading in zip(columns, headings):
            tree.heading(column, text=heading)
        tree.tag_configure("Critical", foreground="#ff657a")
        tree.tag_configure("High", foreground="#ff9f43")
        tree.tag_configure("Medium", foreground="#feca57")
        tree.tag_configure("Low", foreground="#48dbfb")
        tree.tag_configure("Info", foreground="#c8d6e5")
        tree.tag_configure("failed", foreground="#ff657a")
        tree.tag_configure("timeout", foreground="#ff9f43")
        tree.tag_configure("degraded", foreground="#feca57")
        tree.tag_configure("running", foreground="#00d2d3")
        tree.tag_configure("finished", foreground="#1dd1a1")
        return tree

    def _configure_columns(self, tree: ttk.Treeview) -> None:
        widths = {
            "target": 180,
            "module": 170,
            "status": 95,
            "tested": 80,
            "hits": 70,
            "findings": 80,
            "duration": 90,
            "error": 360,
            "tool": 110,
            "profile": 210,
            "rc": 70,
            "timeout": 80,
            "time": 150,
            "severity": 80,
            "title": 420,
            "source": 130,
            "fingerprint": 145,
            "level": 80,
            "message": 760,
        }
        for column in tree["columns"]:
            tree.column(column, width=widths.get(column, 120), minwidth=60, stretch=True)

    def choose_folder(self) -> None:
        chosen = filedialog.askdirectory(initialdir=str(self.base_dir), title="Selecciona carpeta de Scan Titan")
        if not chosen:
            return
        self.base_dir = Path(chosen).resolve()
        self.reports_dir = resolve_reports_dir(self.base_dir)
        self.runtime_file = self.reports_dir / RUNTIME_NAME
        self.path_var.set(str(self.base_dir))
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
        data = read_json(self.runtime_file)
        if not data:
            self._render_fallback()
        else:
            self._render_runtime(data)
        self.after(REFRESH_MS, self.refresh)

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

        self._set_status("FALLBACK", "#f39c12" if latest_report or external_rows or state else "#43505c")
        self.global_bar["value"] = 100 if latest_report else 0
        self.module_bar["value"] = 0
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
        if latest_report or external_rows or state:
            self.footer_var.set(
                f"Modo fallback activo | Runtime ausente: {self.runtime_file} | "
                "reinicia Main.py para telemetria viva"
            )
        else:
            self.footer_var.set(f"Esperando {self.runtime_file}")

    def _render_runtime(self, data: dict[str, Any]) -> None:
        status = safe_text(data.get("status") or "unknown").upper()
        self._set_status(status, self._status_color(status.lower()))
        global_percent = self._float_value(data.get("global_percent"))
        module_percent = self._float_value(data.get("module_percent"))
        self.global_bar["value"] = global_percent
        self.module_bar["value"] = module_percent
        self.global_text.configure(text=f"{global_percent:.2f}%")
        self.module_text.configure(text=f"{module_percent:.2f}%")

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
        self.metric_vars["elapsed"].set(format_seconds(data.get("elapsed_seconds")))

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
        updated = data.get("updated_at") or ""
        last_error = safe_text(data.get("last_error") or "", 240)
        last_warning = safe_text(data.get("last_warning") or "", 240)
        footer = f"Actualizado {update_age_text(updated)} | Runtime: {self.runtime_file}"
        if last_error:
            footer += f" | Ultimo error: {last_error}"
        elif last_warning:
            footer += f" | Ultimo aviso: {last_warning}"
        self.footer_var.set(footer)

    def _set_status(self, text: str, color: str) -> None:
        self.status_label.configure(text=text, bg=color)

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
        tree.delete(*tree.get_children())
        for row in rows:
            tags: list[str] = []
            values = tuple("" if item is None else item for item in row)
            for value in values:
                text = str(value)
                if text in SEVERITIES:
                    tags.append(text)
                if text in {"running", "finished", "degraded", "failed", "timeout"}:
                    tags.append(text)
            tree.insert("", "end", values=values, tags=tuple(tags))

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
    sample = {
        "status": "running",
        "global_percent": 51.5,
        "module_percent": 25,
        "findings": {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5},
        "modules": [{"module": "headers", "status": "running"}],
        "external_tools": [{"tool": "nmap", "profile": "service_top_1000", "status": "finished"}],
        "recent_findings": [{"severity": "High", "title": "demo"}],
        "events": [{"level": "INFO", "message": "demo"}],
    }
    assert abs(float(sample["global_percent"]) - 51.5) < 0.01
    assert sample["findings"]["High"] == 2
    assert format_seconds(3661) == "1h 01m 01s"
    assert safe_text("a\nb") == "a b"
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
