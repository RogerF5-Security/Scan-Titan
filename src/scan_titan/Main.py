# -*- coding: utf-8 -*-
"""
Scan Titan - Orquestador asincrono empresarial

Escaner zero-touch de vulnerabilidades para auditorias autorizadas.
Ejecutar con:

    python main.py

El escaner lee automaticamente targets/targets.txt, carga wordlists, ejecuta recon,
dispara modulos asincronos de vulnerabilidades, orquesta Nmap/Nuclei cuando existen,
actualiza reports/Recon_Matrix.xlsx, escribe reportes TXT TITAN y deduplica hallazgos con
Primera Deteccion / Ultima Deteccion en reports/scan_titan_state.json.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import html
import ipaddress
import json
import os
import re
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
import warnings
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp

from modules import DEFAULT_MODULES
from modules.common import (
    AsyncHttpClient,
    Finding,
    ScanContext,
    ScanLimits,
    ScanPolicy,
    SEVERITY_ORDER,
    Target,
    build_manual_command,
    canonical_vulnerability_id,
    category_label_es,
    correlate_findings,
    clean_text,
    confidence_label_es,
    evidence_strength_label_es,
    false_positive_risk_label_es,
    field_label_es,
    finding_quality_exclusion,
    is_authentication_url,
    is_soft_auth_redirect,
    normalize_severity,
    severity_label_es,
    soft_auth_redirect_reason,
    translate_visible_text,
    vulnerability_occurrence_key,
)
from evidence_manager import EvidenceManager
from knowledge_manager import KnowledgeBase
from owasp_2025 import normalize_owasp_2025
from recon_manager import ReconMatrixManager
from sitemap_manager import ReconSiteMapManager

try:
    from technical_detail_exporter import TechnicalDetailExporter, TechnicalDetailOptions
except Exception:

    class TechnicalDetailOptions:  # type: ignore[no-redef]
        """Public build fallback: private workbook exports are disabled."""

        enabled = False

        def __init__(self) -> None:
            self.enabled = False
            self.output_dir = Path("reports") / "technical_details"
            self.audit_id = ""

        @classmethod
        def from_config(
            cls,
            _config: dict[str, Any],
            _base_dir: Path,
            reports_dir: Path,
        ) -> "TechnicalDetailOptions":
            instance = cls()
            instance.output_dir = reports_dir / "technical_details"
            return instance

    class TechnicalDetailExporter:  # type: ignore[no-redef]
        """No-op exporter used by the public community template."""

        def __init__(self, _options: TechnicalDetailOptions) -> None:
            pass

        def export_results(self, _results: list[dict[str, Any]]) -> Path | None:
            return None

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    yaml = None  # type: ignore[assignment]
    YAML_AVAILABLE = False

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
except ImportError:

    class Fore:  # type: ignore[no-redef]
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = LIGHTRED_EX = ""

    class Style:  # type: ignore[no-redef]
        RESET_ALL = ""


def configure_output_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


configure_output_encoding()
warnings.filterwarnings("ignore", category=ResourceWarning, message=r".*unclosed transport.*")


_DEFAULT_UNRAISABLE_HOOK = sys.unraisablehook


def _is_windows_asyncio_transport_noise(exc: BaseException | None, message: str = "", context: Any = None) -> bool:
    if exc is None:
        return False
    if not isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError)):
        return False
    code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
    if code not in {64, 995, 10053, 10054, 10058}:
        return False
    haystack = " ".join([str(message or ""), str(exc), str(context or "")]).lower()
    return any(
        token in haystack
        for token in (
            "_proactorbasepipetransport",
            "proactor",
            "_call_connection_lost",
            "connection_lost",
            "pipe",
            "socket.shutdown",
            "connection reset",
            "se ha forzado la interrup",
        )
    )


def _scan_titan_unraisable_hook(unraisable: Any) -> None:
    message = str(getattr(unraisable, "exc_value", ""))
    if getattr(unraisable, "exc_type", None) is ValueError and "I/O operation on closed pipe" in message:
        return
    if _is_windows_asyncio_transport_noise(getattr(unraisable, "exc_value", None), message, unraisable):
        return
    _DEFAULT_UNRAISABLE_HOOK(unraisable)


sys.unraisablehook = _scan_titan_unraisable_hook


def install_asyncio_noise_filter() -> None:
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()

    def handler(active_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        exc = context.get("exception")
        message = str(context.get("message", ""))
        context_hint = {
            "handle": context.get("handle"),
            "transport": context.get("transport"),
            "protocol": context.get("protocol"),
        }
        if _is_windows_asyncio_transport_noise(exc, message, context_hint):
            return
        if previous_handler:
            previous_handler(active_loop, context)
        else:
            active_loop.default_exception_handler(context)

    loop.set_exception_handler(handler)

def _path_from_env(name: str, default: Path) -> Path:
    return Path(os.environ.get(name, str(default))).expanduser().resolve()


def _first_existing(*paths: Path) -> Path:
    for path in paths:
        if path.exists():
            return path
    return paths[0]


ENGINE_DIR = Path(__file__).resolve().parent
BASE_DIR = _path_from_env("SCAN_TITAN_BASE_DIR", ENGINE_DIR)
TARGETS_FILE = _path_from_env(
    "SCAN_TITAN_TARGETS_FILE",
    _first_existing(BASE_DIR / "targets" / "targets.txt", BASE_DIR / "targets.txt"),
)
TARGETS_DIR = _path_from_env("SCAN_TITAN_TARGETS_DIR", BASE_DIR / "targets")
WORDLISTS_DIR = _path_from_env("SCAN_TITAN_WORDLISTS_DIR", BASE_DIR / "wordlists")
REPORTS_DIR = _path_from_env(
    "SCAN_TITAN_REPORTS_DIR",
    _first_existing(BASE_DIR / "reports", BASE_DIR / "audit_reports"),
)
HISTORY_DIR = _path_from_env(
    "SCAN_TITAN_HISTORY_DIR",
    _first_existing(REPORTS_DIR / "history", BASE_DIR / "audit_history"),
)
STATE_FILE = _path_from_env("SCAN_TITAN_STATE_FILE", REPORTS_DIR / "scan_titan_state.json")
RUNTIME_FILE = _path_from_env("SCAN_TITAN_RUNTIME_FILE", REPORTS_DIR / "scan_titan_runtime.json")
RECON_FILE = _path_from_env("SCAN_TITAN_RECON_FILE", REPORTS_DIR / "Recon_Matrix.xlsx")
CONFIG_FILE = _path_from_env(
    "SCAN_TITAN_CONFIG_FILE",
    _first_existing(BASE_DIR / "config" / "config.yaml", BASE_DIR / "config.yaml"),
)
KNOWLEDGE_FILE = _path_from_env(
    "SCAN_TITAN_KNOWLEDGE_FILE",
    _first_existing(BASE_DIR / "data" / "scan_titan_knowledge.json", BASE_DIR / "scan_titan_knowledge.json"),
)
SCAN_VERSION = "TITAN v22.0.1 COMMUNITY ZERO-TOUCH"
HEADER_SEPARATOR = "=" * 72
REPORT_SEPARATOR = "─" * 72


class RuntimeTelemetry:
    SCHEMA = "scan_titan_runtime_v1"

    def __init__(self, path: Path) -> None:
        self.path = path
        self.started_monotonic = time.monotonic()
        self.state: dict[str, Any] = {
            "schema": self.SCHEMA,
            "scanner": SCAN_VERSION,
            "base_dir": str(BASE_DIR),
            "pid": None,
            "status": "idle",
            "started_at": "",
            "updated_at": "",
            "elapsed_seconds": 0.0,
            "target_total": 0,
            "target_index": 0,
            "targets_completed": 0,
            "current_target": "",
            "current_phase": "",
            "current_module": "",
            "current_detail": "",
            "module_tested": 0,
            "module_total": 0,
            "module_hits": 0,
            "module_percent": 0.0,
            "global_percent": 0.0,
            "last_error": "",
            "last_warning": "",
            "finding_unique": 0,
            "finding_occurrences": 0,
            "findings": {severity: 0 for severity in ("Critical", "High", "Medium", "Low", "Info")},
            "recent_findings": [],
            "events": [],
            "modules": [],
            "external_tools": [],
        }
        self._module_started = 0.0
        self._target_started = 0.0
        self._target_names: list[str] = []
        self._current_module_index = 0
        self._module_total_estimate = max(1, len(DEFAULT_MODULES))
        self._active_module_name = ""

    def start(self, targets: list[Target], config: Any) -> None:
        self.started_monotonic = time.monotonic()
        self._target_names = [target.display for target in targets]
        self.state.update(
            {
                "pid": os.getpid(),
                "status": "running",
                "started_at": now_text(),
                "profile": config.policy.profile,
                "full_power": bool(config.full_power),
                "target_total": len(targets),
                "target_index": 0,
                "targets_completed": 0,
                "current_phase": "startup",
                "current_module": "",
                "last_error": "",
                "last_warning": "",
                "finding_unique": 0,
                "finding_occurrences": 0,
                "modules": [],
                "external_tools": [],
                "events": [],
            }
        )
        self.event("INFO", f"Sesion iniciada con {len(targets)} objetivo(s)")
        self.write()

    def finish(self, status: str = "finished") -> None:
        self.state["status"] = status
        self.state["current_phase"] = status
        self.state["current_module"] = ""
        self.event("INFO", f"Session {status}")
        self.write()

    def phase(self, name: str, detail: str = "") -> None:
        self.state["current_phase"] = name
        if detail:
            self.state["current_detail"] = detail
        self.event("PHASE", f"{name}: {detail}" if detail else name)
        self.write()

    def target_start(self, target: Target) -> None:
        self._target_started = time.monotonic()
        try:
            index = self._target_names.index(target.display) + 1
        except ValueError:
            index = int(self.state.get("target_index") or 0) + 1
        self._current_module_index = 0
        self.state.update(
            {
                "status": "running",
                "target_index": index,
                "current_target": target.display,
                "current_target_url": target.url,
                "current_target_ip": target.ip,
                "current_phase": "target",
                "current_module": "",
                "current_detail": target.url,
                "module_tested": 0,
                "module_total": 0,
                "module_hits": 0,
                "module_percent": 0.0,
            }
        )
        self.event("TARGET", f"Started {target.display}")
        self.write()

    def target_end(self, target: Target, findings: list[Finding], duration: float) -> None:
        completed = max(int(self.state.get("targets_completed") or 0), int(self.state.get("target_index") or 0))
        total_targets = max(1, int(self.state.get("target_total") or 1))
        self.state["targets_completed"] = completed
        self.state["global_percent"] = round(min(100.0, (completed / total_targets) * 100.0), 2)
        self._set_counts(findings)
        self.event("TARGET", f"Objetivo finalizado {target.display} en {duration:.1f}s con {len(findings)} hallazgo(s)")
        self.write()

    def target_failed(self, target: Target, error: Any) -> None:
        self.state["last_error"] = clean_text(error, 600)
        self.event("ERROR", f"Objetivo fallido {target.display}: {error}")
        self.write()

    def module_start(self, target: Target, module_name: str, total: int, timeout: int) -> None:
        self._module_started = time.monotonic()
        self._active_module_name = module_name
        self._current_module_index += 1
        self.state.update(
            {
                "current_phase": "module",
                "current_module": module_name,
                "current_detail": f"timeout={timeout}s",
                "module_tested": 0,
                "module_total": int(total or 0),
                "module_hits": 0,
                "module_percent": 0.0,
            }
        )
        self._upsert_module(
            module_name,
            {
                "target": target.display,
                "module": module_name,
                "status": "running",
                "started_at": now_text(),
                "duration_seconds": 0.0,
                "tested": 0,
                "hits": 0,
                "findings": 0,
                "timeout_seconds": timeout,
            },
        )
        self.event("MODULE", f"{module_name} iniciado")
        self.write()

    def heartbeat(self, module: str, detail: str, tested: int, hits: int) -> None:
        total = int(self.state.get("module_total") or 0)
        percent = min(100.0, (float(tested) / total) * 100.0) if total > 0 else 0.0
        active_module = self._active_module_name or module
        visible_detail = detail if module == active_module else f"{module}: {detail}"
        self.state.update(
            {
                "current_module": active_module,
                "current_detail": clean_text(visible_detail, 220),
                "module_tested": tested,
                "module_hits": hits,
                "module_percent": round(percent, 2),
            }
        )
        self._upsert_module(
            active_module,
            {
                "target": self.state.get("current_target", ""),
                "module": active_module,
                "detail": clean_text(f"{module}: {detail}", 220),
                "tested": tested,
                "hits": hits,
                "duration_seconds": round(time.monotonic() - self._module_started, 1) if self._module_started else 0.0,
            },
        )
        self._update_global_percent(percent / 100.0 if total else 0.0)
        self.write()

    def module_end(self, module: str, findings: list[Finding], status: str = "finished", error: str = "") -> None:
        if error and status in {"failed", "timeout"}:
            self.state["last_error"] = clean_text(error, 600)
        elif error:
            self.state["last_warning"] = clean_text(error, 600)
        self.state["module_percent"] = 100.0 if status == "finished" else self.state.get("module_percent", 0.0)
        self._upsert_module(
            module,
            {
                "status": status,
                "finished_at": now_text(),
                "duration_seconds": round(time.monotonic() - self._module_started, 1) if self._module_started else 0.0,
                "findings": len(findings),
                "error": clean_text(error, 500) if error else "",
            },
        )
        estados = {
            "finished": "finalizado",
            "failed": "fallido",
            "timeout": "timeout",
            "skipped": "omitido",
            "running": "en ejecucion",
        }
        self.event("MODULE", f"{module} {estados.get(status, status)} con {len(findings)} hallazgo(s)")
        self._active_module_name = ""
        self.write()

    def module_activity(self, module: str, detail: str, http: dict[str, Any]) -> None:
        self.state["current_detail"] = detail
        self.state["http_activity"] = http
        self._upsert_module(module, {
            "detail": detail,
            "http_activity": http,
            "duration_seconds": round(time.monotonic() - self._module_started, 1),
        })
        self.write()

    def external_start(self, tool: str, profile: str, target: str, command: list[str] | None = None) -> None:
        key = f"{tool}:{profile}"
        self.state.update(
            {
                "current_phase": "external",
                "current_module": key,
                "current_detail": target,
            }
        )
        self._upsert_external(
            key,
            {
                "tool": tool,
                "profile": profile,
                "target": target,
                "status": "running",
                "started_at": now_text(),
                "duration_seconds": 0.0,
                "command": command or [],
                "returncode": "",
                "findings": 0,
                "timed_out": False,
                "error": "",
            },
        )
        self.event("TOOL", f"{key} iniciado")
        self.write()

    def external_heartbeat(self, process_id: int | None, elapsed: float) -> None:
        key = str(self.state.get("current_module") or "")
        if self.state.get("current_phase") != "external" or ":" not in key:
            return
        tool, profile = key.split(":", 1)
        target = str(self.state.get("current_target") or "")
        self.state["current_detail"] = f"{target} | running {elapsed:.0f}s | pid={process_id or '-'}"
        self._upsert_external(
            key,
            {
                "tool": tool,
                "profile": profile,
                "target": target,
                "status": "running",
                "pid": process_id,
                "duration_seconds": round(elapsed, 1),
            },
        )
        self.write()

    def external_end(
        self,
        tool: str,
        profile: str,
        returncode: int | None,
        timed_out: bool,
        duration: float,
        parsed_count: int,
        error: str = "",
    ) -> None:
        key = f"{tool}:{profile}"
        if timed_out and parsed_count > 0:
            status = "degraded"
        elif timed_out:
            status = "timeout"
        elif returncode not in {0, None} and parsed_count > 0:
            status = "degraded"
        elif returncode not in {0, None}:
            status = "failed"
        else:
            status = "finished"
        if error and status in {"failed", "timeout"}:
            self.state["last_error"] = clean_text(error, 600)
        elif error and status == "degraded":
            self.state["last_warning"] = clean_text(error, 600)
        self._upsert_external(
            key,
            {
                "status": status,
                "finished_at": now_text(),
                "duration_seconds": round(float(duration or 0), 1),
                "returncode": "" if returncode is None else returncode,
                "findings": parsed_count,
                "timed_out": bool(timed_out),
                "error": clean_text(error, 700) if error else "",
            },
        )
        estados = {
            "finished": "finalizado",
            "failed": "fallido",
            "timeout": "timeout",
            "degraded": "degradado",
            "running": "en ejecucion",
        }
        self.event("TOOL", f"{key} {estados.get(status, status)} parseados={parsed_count}")
        self.write()

    def add_findings(self, findings: list[Finding]) -> None:
        if not findings:
            return
        counts = Counter(normalize_severity(finding.severity) for finding in findings)
        total_counts = self.state.setdefault("findings", {severity: 0 for severity in ("Critical", "High", "Medium", "Low", "Info")})
        for severity, count in counts.items():
            total_counts[severity] = int(total_counts.get(severity, 0)) + int(count)
        recent = list(self.state.get("recent_findings", []))
        for finding in findings:
            recent.insert(
                0,
                {
                    "time": now_text(),
                    "severity": finding.severity,
                    "target": finding.target,
                    "title": finding.title,
                    "source": finding.source,
                    "fingerprint": finding.fingerprint[:16],
                },
            )
        self.state["recent_findings"] = recent[:40]

    def set_counts_from_records(self, records: list[dict[str, Any]]) -> None:
        counts = Counter(normalize_severity(record.get("severity", "Info")) for record in records)
        self.state["findings"] = {severity: counts.get(severity, 0) for severity in ("Critical", "High", "Medium", "Low", "Info")}
        self.state["finding_unique"] = len(records)
        self.state["finding_occurrences"] = sum(max(1, int(record.get("occurrences") or 1)) for record in records)
        self.write()

    def event(self, level: str, message: str) -> None:
        events = list(self.state.get("events", []))
        events.insert(0, {"time": now_text(), "level": level, "message": clean_text(message, 360)})
        self.state["events"] = events[:80]

    def write(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.state["updated_at"] = now_text()
            self.state["elapsed_seconds"] = round(time.monotonic() - self.started_monotonic, 1)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.path)
        except Exception:
            pass

    def _upsert_module(self, module: str, values: dict[str, Any]) -> None:
        items = list(self.state.get("modules", []))
        values.setdefault("module", module)
        values.setdefault("target", self.state.get("current_target", ""))
        for item in items:
            if item.get("module") == module and item.get("target") == values.get("target", item.get("target")):
                item.update(values)
                break
        else:
            items.insert(0, values)
        self.state["modules"] = items[:80]

    def _upsert_external(self, key: str, values: dict[str, Any]) -> None:
        items = list(self.state.get("external_tools", []))
        values.setdefault("target", self.state.get("current_target", ""))
        target = str(values.get("target") or "")
        for item in items:
            if f"{item.get('tool')}:{item.get('profile')}" == key and str(item.get("target") or "") == target:
                item.update(values)
                break
        else:
            items.insert(0, values)
        self.state["external_tools"] = items[:60]

    def _set_counts(self, findings: list[Finding]) -> None:
        counts = Counter(normalize_severity(finding.severity) for finding in findings)
        self.state["findings"] = {severity: counts.get(severity, 0) for severity in ("Critical", "High", "Medium", "Low", "Info")}
        self.state["finding_unique"] = len({finding.fingerprint for finding in findings})
        self.state["finding_occurrences"] = len(findings)

    def _update_global_percent(self, module_fraction: float) -> None:
        total_targets = max(1, int(self.state.get("target_total") or 1))
        completed = max(0, int(self.state.get("targets_completed") or 0))
        module_slot = min(1.0, max(0.0, (self._current_module_index - 1 + module_fraction) / self._module_total_estimate))
        current_target_index = max(0, int(self.state.get("target_index") or 0) - 1)
        base = max(completed, current_target_index)
        calculated = round(min(100.0, ((base + module_slot) / total_targets) * 100.0), 2)
        previous = float(self.state.get("global_percent") or 0.0)
        self.state["global_percent"] = max(previous, calculated)

class Console:
    @staticmethod
    def banner() -> None:
        print(
            f"""
{Fore.RED}  ███████╗ ██████╗ █████╗ ███╗   ██╗    ████████╗██╗████████╗ █████╗ ███╗   ██╗
{Fore.RED}  ██╔════╝██╔════╝██╔══██╗████╗  ██║    ╚══██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║
{Fore.RED}  ███████╗██║     ███████║██╔██╗ ██║       ██║   ██║   ██║   ███████║██╔██╗ ██║
{Fore.RED}  ╚════██║██║     ██╔══██║██║╚██╗██║       ██║   ██║   ██║   ██╔══██║██║╚██╗██║
{Fore.RED}  ███████║╚██████╗██║  ██║██║ ╚████║       ██║   ██║   ██║   ██║  ██║██║ ╚████║
{Fore.RED}  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝       ╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝
{Fore.YELLOW}        [ SCAN TITAN :: WALL-BREACH VULNERABILITY ENGINE ]
{Fore.CYAN}        [ ZERO-TOUCH | RECON | DAST | NMAP | NUCLEI | EVIDENCE ]
{Fore.MAGENTA}        [ SCAN TITAN COMMUNITY | TATAKAE | ⚔️ v22.0.1 ⚔️ ]
"""
        )

    @staticmethod
    def phase(message: str) -> None:
        print(f"\n{Fore.BLUE}{HEADER_SEPARATOR}")
        print(f"{Fore.BLUE}  {message}")
        print(f"{Fore.BLUE}{HEADER_SEPARATOR}{Style.RESET_ALL}", flush=True)

    @staticmethod
    def step(message: str) -> None:
        print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}", flush=True)

    @staticmethod
    def heartbeat(module: str, detail: str, tested: int, found: int) -> None:
        print(
            f"{Fore.CYAN}[~] {module:<18} probadas={tested:<5} hallazgos={found:<4} "
            f"{clean_text(detail, 90)}{Style.RESET_ALL}",
            flush=True,
        )

    @staticmethod
    def ok(message: str) -> None:
        print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}", flush=True)

    @staticmethod
    def warn(message: str) -> None:
        print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}", flush=True)

    @staticmethod
    def error(message: str) -> None:
        print(f"{Fore.RED}[x] {message}{Style.RESET_ALL}", flush=True)

    @staticmethod
    def finding(finding: Finding) -> None:
        if not getattr(finding, "manual_command", ""):
            finding.manual_command = build_manual_command(finding)
        if finding.severity == "Info":
            print(
                f"{Fore.WHITE}[INFO] {category_label_es(finding.category)}: "
                f"{translate_visible_text(finding.title)}{Style.RESET_ALL}"
            )
            return
        color = {
            "Critical": Fore.LIGHTRED_EX,
            "High": Fore.RED,
            "Medium": Fore.YELLOW,
            "Low": Fore.CYAN,
        }.get(finding.severity, Fore.WHITE)
        print(f"\n{color}{REPORT_SEPARATOR}")
        print(
            f"{color}HALLAZGO CONFIRMADO | "
            f"{severity_label_es(finding.severity).upper():<8} | "
            f"{translate_visible_text(finding.title)}"
        )
        print(f"{color}{REPORT_SEPARATOR}{Style.RESET_ALL}")
        fields = [
            ("Vulnerability ID", finding.canonical_id),
            ("Category", finding.category),
            ("Target", finding.target),
            ("URL", finding.url),
            ("Endpoint", finding.endpoint),
            ("Param", finding.param),
            ("Method", finding.method),
            ("Payload", finding.payload),
            ("HTTP", finding.status),
            ("Size", finding.size),
            ("Time", finding.elapsed),
            ("Evidence", finding.evidence),
            ("Detected By", ", ".join(finding.correlated_sources or [finding.source])),
            ("CWE", finding.cwe),
            ("OWASP", finding.owasp),
            ("CVSS", finding.cvss),
            ("Impact", finding.impact),
            ("Remediation", finding.remediation or finding.recommendation),
            ("Manual Test", finding.manual_command),
            ("Confidence", finding.confidence),
            ("Evidence Strength", finding.evidence_strength),
            ("False Positive Risk", finding.false_positive_risk),
            ("Source", finding.source),
            ("Fingerprint", finding.fingerprint[:16]),
        ]
        for label, value in fields:
            if value in ("", None):
                continue
            limit = 1800 if label in {"Evidence", "Impact", "Remediation"} else 700
            if label == "Manual Test":
                display_value = clean_text(value, limit)
            elif label == "Category":
                display_value = category_label_es(value)
            elif label == "Confidence":
                display_value = confidence_label_es(value)
            elif label == "Evidence Strength":
                display_value = evidence_strength_label_es(value)
            elif label == "False Positive Risk":
                display_value = false_positive_risk_label_es(value)
            else:
                display_value = translate_visible_text(value)
            print(f"  {field_label_es(label):<24}: {clean_text(display_value, limit)}")


class RuntimeControl:
    def __init__(self) -> None:
        self._pause_event = asyncio.Event()
        self._pause_event.set()
        self.finish_requested = False
        self._listener_active = True
        self._paused_logged = False
        self.telemetry: Any | None = None

    @property
    def is_paused(self) -> bool:
        return not self._pause_event.is_set()

    def pause(self) -> None:
        if self.finish_requested:
            return
        if not self.is_paused:
            self._pause_event.clear()
            self._paused_logged = False
            Console.warn("SCAN TITAN EN PAUSA | Presione R para reanudar o F para finalizar con dashboard.")
            if self.telemetry:
                self.telemetry.state["status"] = "paused"
                self.telemetry.event("CONTROL", "Scan paused by operator")
                self.telemetry.write()

    def resume(self) -> None:
        if self.finish_requested:
            return
        if self.is_paused:
            self._pause_event.set()
            Console.ok("SCAN TITAN REANUDADO")
            if self.telemetry:
                self.telemetry.state["status"] = "running"
                self.telemetry.event("CONTROL", "Scan resumed by operator")
                self.telemetry.write()

    def request_finish(self) -> None:
        if self.finish_requested:
            return
        self.finish_requested = True
        self._pause_event.set()
        Console.warn("FINALIZACION ORDENADA SOLICITADA | Los reportes incluiran lo encontrado hasta ahora.")
        if self.telemetry:
            self.telemetry.state["status"] = "finishing"
            self.telemetry.event("CONTROL", "Finalizacion controlada solicitada por el operador")
            self.telemetry.write()

    async def wait_if_paused(self) -> None:
        while self.is_paused and not self.finish_requested:
            if not self._paused_logged:
                self._paused_logged = True
                Console.warn("Escaneo en pausa. Esperando R=reanudar o F=finalizar.")
            await asyncio.sleep(0.5)

    async def keyboard_loop(self) -> None:
        try:
            import msvcrt
        except ImportError:
            Console.warn("Runtime hotkeys unavailable on this platform.")
            return
        Console.ok("Controles en ejecucion: P=pausa | R=reanudar | F=finalizar+dashboard | Ctrl+C=detencion dura")
        while self._listener_active and not self.finish_requested:
            try:
                if msvcrt.kbhit():
                    key = msvcrt.getwch().lower()
                    if key == "p":
                        self.pause()
                    elif key == "r":
                        self.resume()
                    elif key == "f":
                        self.request_finish()
                await asyncio.sleep(0.2)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                Console.warn(f"Runtime hotkey listener stopped: {exc}")
                return

    def stop_listener(self) -> None:
        self._listener_active = False
        self._pause_event.set()


class CleanupManager:
    TRASH_SUFFIXES = {".tmp", ".temp", ".bak", ".old", ".swp", ".swo", ".part", ".retry", ".pid", ".cache", ".log"}
    TRASH_NAMES = {"thumbs.db", "desktop.ini", ".ds_store", "scan.tmp", "targets.tmp"}
    TRASH_PREFIXES = ("ffuf_", "nmap_", "nuclei_", "scan_", "tmp_", "temp_", "~")
    PROTECTED = {"wordlists", "audit_reports", "reports", "config", "src", "data", "templates"}

    def __init__(self, targets_dir: Path) -> None:
        self.targets_dir = targets_dir.resolve()

    def run(self) -> None:
        self.targets_dir.mkdir(parents=True, exist_ok=True)
        deleted = 0
        for path in self.targets_dir.rglob("*"):
            try:
                if path.is_dir() or path.is_symlink():
                    continue
                resolved = path.resolve()
                if any(part.lower() in self.PROTECTED for part in resolved.parts):
                    continue
                if self._is_trash(path):
                    path.unlink()
                    deleted += 1
            except Exception as exc:
                Console.warn(f"Limpieza omitio {path}: {exc}")
        Console.ok(f"Cleanup targets/: {deleted} temporary file(s) removed")

    def _is_trash(self, path: Path) -> bool:
        name = path.name.lower()
        return (
            name in self.TRASH_NAMES
            or path.suffix.lower() in self.TRASH_SUFFIXES
            or any(name.startswith(prefix) for prefix in self.TRASH_PREFIXES)
        )


class PolicyEngine:
    MODULE_GROUPS = {
        "recon": {"recon_surface", "headers", "infra_network", "crypto_tls"},
        "mapping": {
            "api_spa",
            "api_dast",
            "site_map",
            "unauthenticated_map",
            "path_discovery",
            "client_side",
            "browser_audit",
        },
        "fuzzing": {"path_discovery", "recon_surface", "unauthenticated_map"},
        "injections": {"sqli", "lfi", "ssrf", "injection", "xss", "client_side"},
        "auth": {"auth_session", "authorization"},
        "advanced": {"advanced_logic", "browser_audit"},
    }

    PROFILE_DEFAULTS = {
        "safe": {
            "allow_state": False,
            "upload": False,
            "bruteforce": False,
            "rate_limit": False,
            "api_json_body": True,
            "browser": False,
            "console_screenshots": False,
        },
        "balanced": {
            "allow_state": True,
            "upload": False,
            "bruteforce": False,
            "rate_limit": True,
            "api_json_body": True,
            "browser": True,
            "console_screenshots": False,
        },
        "precision": {
            "allow_state": True,
            "upload": True,
            "bruteforce": False,
            "rate_limit": True,
            "api_json_body": True,
            "browser": True,
            "console_screenshots": False,
        },
        "daily": {
            "allow_state": True,
            "upload": False,
            "bruteforce": False,
            "rate_limit": True,
            "api_json_body": True,
            "browser": True,
            "console_screenshots": False,
        },
        "deep": {
            "allow_state": True,
            "upload": True,
            "bruteforce": True,
            "rate_limit": True,
            "api_json_body": True,
            "browser": True,
            "console_screenshots": False,
        },
        "zero-touch": {
            "allow_state": True,
            "upload": True,
            "bruteforce": False,
            "rate_limit": True,
            "api_json_body": True,
            "browser": True,
            "console_screenshots": False,
        },
    }

    def __init__(self, config_data: dict[str, Any], args: argparse.Namespace) -> None:
        self.config_data = config_data
        self.args = args

    def build(self) -> ScanPolicy:
        scan_cfg = self._section("scan")
        active_cfg = self._section("active_testing")
        api_cfg = self._section("api_dast")
        browser_cfg = self._section("browser")
        evidence_cfg = self._section("evidence")
        tools_cfg = self._section("tools")
        external_cfg = self._section("external_observability")
        requested_profile = str(
            getattr(self.args, "profile", "")
            or scan_cfg.get("profile", "")
            or "zero-touch"
        ).strip().lower()
        profile = "deep" if getattr(self.args, "full", False) else requested_profile
        if profile not in self.PROFILE_DEFAULTS:
            profile = "zero-touch"
        defaults = self.PROFILE_DEFAULTS[profile]
        policy = ScanPolicy(
            profile=profile,
            enabled_modules=self._configured_modules("enabled_modules"),
            disabled_modules=self._configured_modules("disabled_modules"),
            skip_external=bool(getattr(self.args, "skip_external", False)),
            enable_nmap=self._tool_enabled(tools_cfg, "nmap", True),
            enable_nuclei=self._tool_enabled(tools_cfg, "nuclei", True),
            enable_ffuf=self._tool_enabled(tools_cfg, "ffuf", True),
            enable_whatweb=self._tool_enabled(tools_cfg, "whatweb", True),
            enable_subfinder=self._tool_enabled(tools_cfg, "subfinder", True),
            enable_wafw00f=self._tool_enabled(tools_cfg, "wafw00f", True),
            enable_zap=self._tool_enabled(tools_cfg, "zap", False),
            external_observability=self._bool(external_cfg, "enabled", True),
            allow_cloud_ssrf=bool(getattr(self.args, "allow_cloud_ssrf", False))
            or self._bool(active_cfg, "allow_cloud_ssrf", False),
            allow_state_changing_api_tests=self._bool(
                active_cfg, "allow_state_changing_api_tests", defaults["allow_state"]
            ),
            perform_upload_attempts=self._bool(active_cfg, "perform_upload_attempts", defaults["upload"]),
            allow_bruteforce=self._bool(active_cfg, "allow_bruteforce", defaults["bruteforce"]),
            allow_rate_limit_probes=self._bool(active_cfg, "allow_rate_limit_probes", defaults["rate_limit"]),
            rate_limit_probe_requests=int(active_cfg.get("rate_limit_probe_requests", 12) or 12),
            api_openapi=self._bool(api_cfg, "openapi", True),
            api_graphql=self._bool(api_cfg, "graphql", True),
            api_sourcemaps=self._bool(api_cfg, "sourcemaps", True),
            api_json_body_tests=self._bool(api_cfg, "json_body_tests", defaults["api_json_body"]),
            enable_browser=self._bool(browser_cfg, "enabled", defaults["browser"]),
            browser_max_pages=int(browser_cfg.get("max_pages", 12) or 12),
            browser_timeout_seconds=int(browser_cfg.get("timeout_seconds", 20) or 20),
            evidence_cards=self._bool(evidence_cfg, "cards", True),
            console_screenshots=self._bool(
                evidence_cfg, "console_screenshot_on_new_findings", defaults["console_screenshots"]
            ),
            browser_evidence=self._bool(evidence_cfg, "browser_screenshots_on_findings", True),
            browser_evidence_max_per_target=int(
                evidence_cfg.get("browser_screenshot_max_per_target", 150) or 150
            ),
            auth_profiles=self._auth_profiles(),
        )
        if getattr(self.args, "full", False):
            policy.skip_external = False
            policy.enable_nmap = True
            policy.enable_nuclei = True
            policy.enable_ffuf = True
            policy.enable_whatweb = True
            policy.enable_subfinder = True
            policy.enable_wafw00f = True
            policy.enable_zap = True
            policy.external_observability = True
            policy.allow_cloud_ssrf = True
            policy.allow_state_changing_api_tests = True
            policy.perform_upload_attempts = True
            policy.allow_bruteforce = True
            policy.allow_rate_limit_probes = True
            policy.api_openapi = True
            policy.api_graphql = True
            policy.api_sourcemaps = True
            policy.api_json_body_tests = True
            policy.enable_browser = True
            policy.evidence_cards = True
            policy.browser_evidence = True
            policy.console_screenshots = bool(getattr(self.args, "console_screenshots", False))
            policy.enabled_modules.clear()
            policy.disabled_modules.clear()
        self._apply_legacy_module_switches(policy)
        if getattr(self.args, "full", False):
            policy.enabled_modules.clear()
            policy.disabled_modules.clear()
        if getattr(self.args, "enable_browser", False):
            policy.enable_browser = True
        if getattr(self.args, "disable_browser", False):
            policy.enable_browser = False
            policy.browser_evidence = False
        if getattr(self.args, "evidence_cards", False):
            policy.evidence_cards = True
        if getattr(self.args, "no_evidence_cards", False):
            policy.evidence_cards = False
        if getattr(self.args, "console_screenshots", False):
            policy.console_screenshots = True
        if getattr(self.args, "enable_zap", False):
            policy.enable_zap = True
        if getattr(self.args, "disable_zap", False):
            policy.enable_zap = False
        return policy

    def _section(self, key: str) -> dict[str, Any]:
        value = self.config_data.get(key, {})
        return value if isinstance(value, dict) else {}

    def _bool(self, section: dict[str, Any], key: str, default: bool) -> bool:
        if key not in section:
            return bool(default)
        value = section.get(key)
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
        return bool(value)

    def _configured_modules(self, key: str) -> set[str]:
        policy_cfg = self._section("module_policy")
        values = policy_cfg.get(key, [])
        if isinstance(values, str):
            values = [values]
        return {str(item).strip().lower() for item in values if str(item).strip()}

    def _tool_enabled(self, tools_cfg: dict[str, Any], name: str, default: bool) -> bool:
        tool_cfg = tools_cfg.get(name, {}) if isinstance(tools_cfg.get(name), dict) else {}
        return self._bool(tool_cfg, "enabled", default)

    def _auth_profiles(self) -> list[dict[str, Any]]:
        raw = self.config_data.get("auth_profiles", [])
        if not isinstance(raw, list):
            return []
        profiles = []
        for item in raw:
            if isinstance(item, dict) and item.get("name"):
                profiles.append(item)
        return profiles[:8]

    def _apply_legacy_module_switches(self, policy: ScanPolicy) -> None:
        modules_cfg = self._section("modules")
        if not modules_cfg:
            return
        if isinstance(modules_cfg.get("active"), dict):
            active_cfg = modules_cfg["active"]
            if active_cfg.get("injections") is False:
                policy.disabled_modules.update(self.MODULE_GROUPS["injections"])
            if active_cfg.get("file_upload") is False:
                policy.perform_upload_attempts = False
            if active_cfg.get("traffic_control") is False:
                policy.allow_rate_limit_probes = False
        if isinstance(modules_cfg.get("auth_api"), dict):
            auth_cfg = modules_cfg["auth_api"]
            if auth_cfg.get("authentication") is False and auth_cfg.get("sessions_api") is False:
                policy.disabled_modules.update(self.MODULE_GROUPS["auth"])
            if auth_cfg.get("bruteforce") is True:
                policy.allow_bruteforce = True
        if isinstance(modules_cfg.get("fuzzing"), dict):
            fuzz_cfg = modules_cfg["fuzzing"]
            if fuzz_cfg.get("directories") is False:
                policy.disabled_modules.add("path_discovery")
                policy.enable_ffuf = False
            if fuzz_cfg.get("nuclei") is False:
                policy.enable_nuclei = False
        if isinstance(modules_cfg.get("mapping"), dict):
            mapping_cfg = modules_cfg["mapping"]
            if mapping_cfg.get("spider") is False:
                policy.disabled_modules.add("browser_audit")
            if mapping_cfg.get("unauthenticated_routes") is False:
                policy.disabled_modules.add("unauthenticated_map")

class RuntimeConfig:
    DEFAULT_MIN_WORDLIST_ENTRIES = 10_000
    DEFAULT_MIN_WORDLIST_TESTS = 10_000
    PAYLOAD_JITTER_MODULES = {
        "api_dast",
        "auth_session",
        "authorization",
        "client_side",
        "injection",
        "lfi",
        "sqli",
        "ssrf",
        "waf_resilience",
        "xss",
    }
    ROUTE_JITTER_MODULES = {
        "api_spa",
        "path_discovery",
        "recon_surface",
        "site_map",
        "unauthenticated_map",
    }
    WORDLIST_HEAVY_MODULES = {
        "api_dast",
        "api_spa",
        "auth_session",
        "authorization",
        "client_side",
        "injection",
        "lfi",
        "path_discovery",
        "recon_surface",
        "sqli",
        "ssrf",
        "ssti",
        "unauthenticated_map",
        "xss",
    }

    def __init__(self, args: argparse.Namespace) -> None:
        config_data = self._load_yaml(CONFIG_FILE)
        scan_cfg = config_data.get("scan", {}) if isinstance(config_data.get("scan"), dict) else {}
        self.full_power = bool(getattr(args, "full", False))
        self.policy = PolicyEngine(config_data, args).build()
        self.runtime_control = RuntimeControl()
        self.telemetry: RuntimeTelemetry | None = None

        self.target = args.target
        self.targets_file = self._path_config(scan_cfg.get("targets_file"), TARGETS_FILE)
        self.targets_dir = self._path_config(scan_cfg.get("targets_dir"), TARGETS_DIR)
        self.timeout = float(
            args.timeout
            if args.timeout is not None
            else (20 if self.full_power else scan_cfg.get("timeout_seconds", 10))
        )
        requested_concurrency = int(
            args.concurrency
            if args.concurrency is not None
            else (20 if self.full_power else scan_cfg.get("http_concurrency", 20))
        )
        requested_target_concurrency = int(
            args.target_concurrency
            if args.target_concurrency is not None
            else (1 if self.full_power else scan_cfg.get("target_concurrency", 1))
        )
        self.concurrency = max(1, min(requested_concurrency, 20))
        self.target_concurrency = max(1, min(requested_target_concurrency, 1))
        requested_max_tests = int(
            args.max_tests
            if args.max_tests is not None
            else (50000 if self.full_power else scan_cfg.get("max_tests_per_module", self.DEFAULT_MIN_WORDLIST_TESTS))
        )
        self.max_tests_per_module = (
            requested_max_tests
            if args.max_tests is not None
            else max(self.DEFAULT_MIN_WORDLIST_TESTS, requested_max_tests)
        )
        requested_wordlist_entries = int(
            args.max_wordlist_entries
            if args.max_wordlist_entries is not None
            else (0 if self.full_power else scan_cfg.get("max_wordlist_entries", self.DEFAULT_MIN_WORDLIST_ENTRIES))
        )
        self.max_wordlist_entries = (
            requested_wordlist_entries
            if args.max_wordlist_entries is not None or requested_wordlist_entries == 0
            else max(self.DEFAULT_MIN_WORDLIST_ENTRIES, requested_wordlist_entries)
        )
        self.delay_seconds = float(
            args.delay if args.delay is not None else scan_cfg.get("delay_seconds", 0.02)
        )
        self.jitter_min_seconds = float(scan_cfg.get("jitter_min_seconds", 0.5))
        self.jitter_max_seconds = float(scan_cfg.get("jitter_max_seconds", 1.5))
        if self.jitter_max_seconds < self.jitter_min_seconds:
            self.jitter_max_seconds = self.jitter_min_seconds
        self.throttle_batch_size = int(scan_cfg.get("throttle_batch_size", 25) or 25)
        self.adaptive_waf_block_threshold = max(
            3, int(scan_cfg.get("adaptive_waf_block_threshold", 6) or 6)
        )
        self.adaptive_plateau_threshold = max(
            4, int(scan_cfg.get("adaptive_plateau_threshold", 8) or 8)
        )
        self.payload_delay_seconds = float(scan_cfg.get("payload_delay_seconds", self.delay_seconds) or 0.0)
        self.payload_jitter_min_seconds = float(scan_cfg.get("payload_jitter_min_seconds", 1.0) or 0.0)
        self.payload_jitter_max_seconds = float(scan_cfg.get("payload_jitter_max_seconds", 2.0) or self.payload_jitter_min_seconds)
        self.payload_throttle_batch_size = int(scan_cfg.get("payload_throttle_batch_size", 1) or 1)
        self.route_delay_seconds = float(scan_cfg.get("route_delay_seconds", self.delay_seconds) or 0.0)
        self.route_jitter_min_seconds = float(scan_cfg.get("route_jitter_min_seconds", 0.5) or 0.0)
        self.route_jitter_max_seconds = float(scan_cfg.get("route_jitter_max_seconds", 1.5) or self.route_jitter_min_seconds)
        self.route_throttle_batch_size = int(scan_cfg.get("route_throttle_batch_size", 10) or 10)
        module_throttles = scan_cfg.get("module_throttle_overrides", {})
        self.module_throttle_overrides = module_throttles if isinstance(module_throttles, dict) else {}
        if self.full_power:
            self.payload_jitter_min_seconds = max(1.0, self.payload_jitter_min_seconds)
            self.payload_jitter_max_seconds = max(2.0, self.payload_jitter_max_seconds)
            self.payload_throttle_batch_size = 1
            self.route_jitter_min_seconds = max(0.5, self.route_jitter_min_seconds)
            self.route_jitter_max_seconds = max(1.5, self.route_jitter_max_seconds)
            self.route_throttle_batch_size = max(5, min(self.route_throttle_batch_size, 10))
        if self.payload_jitter_max_seconds < self.payload_jitter_min_seconds:
            self.payload_jitter_max_seconds = self.payload_jitter_min_seconds
        if self.route_jitter_max_seconds < self.route_jitter_min_seconds:
            self.route_jitter_max_seconds = self.route_jitter_min_seconds
        self.module_test_budgets = {} if self.full_power else self._int_map(scan_cfg.get("module_test_budgets", {}))
        self.module_timeout_overrides = (
            {} if self.full_power else self._int_map(scan_cfg.get("module_timeout_overrides", {}), minimum=0)
        )
        self.verify_tls = bool(args.verify_tls or scan_cfg.get("verify_tls", False))
        tools_cfg = config_data.get("tools", {}) if isinstance(config_data.get("tools"), dict) else {}
        nmap_cfg = tools_cfg.get("nmap", {}) if isinstance(tools_cfg.get("nmap"), dict) else {}
        nuclei_cfg = tools_cfg.get("nuclei", {}) if isinstance(tools_cfg.get("nuclei"), dict) else {}
        ffuf_cfg = tools_cfg.get("ffuf", {}) if isinstance(tools_cfg.get("ffuf"), dict) else {}
        whatweb_cfg = tools_cfg.get("whatweb", {}) if isinstance(tools_cfg.get("whatweb"), dict) else {}
        subfinder_cfg = tools_cfg.get("subfinder", {}) if isinstance(tools_cfg.get("subfinder"), dict) else {}
        wafw00f_cfg = tools_cfg.get("wafw00f", {}) if isinstance(tools_cfg.get("wafw00f"), dict) else {}
        zap_cfg = tools_cfg.get("zap", {}) if isinstance(tools_cfg.get("zap"), dict) else {}
        self.nmap_timeout = self._timeout_value(
            args.nmap_timeout,
            0 if self.full_power else nmap_cfg.get("timeout_seconds", 0),
        )
        self.nuclei_timeout = self._timeout_value(
            args.nuclei_timeout,
            0 if self.full_power else nuclei_cfg.get("timeout_seconds", 0),
        )
        self.nuclei_templates_path = str(nuclei_cfg.get("templates_path", "nuclei-templates") or "nuclei-templates")
        self.nuclei_system_resolvers = bool(nuclei_cfg.get("system_resolvers", True))
        self.nuclei_disable_host_error_skip = bool(nuclei_cfg.get("disable_host_error_skip", True))
        self.nuclei_max_seed_urls = max(1, min(int(nuclei_cfg.get("max_seed_urls", 60) or 60), 250))
        self.whatweb_aggression = int(whatweb_cfg.get("aggression", 3 if self.full_power else 1) or 1)
        if self.full_power:
            self.whatweb_aggression = max(self.whatweb_aggression, 4)
        self.whatweb_aggression = max(1, min(self.whatweb_aggression, 4))
        self.whatweb_follow_redirect = str(whatweb_cfg.get("follow_redirect", "always") or "always")
        self.whatweb_max_redirects = int(whatweb_cfg.get("max_redirects", 10) or 10)
        self.whatweb_open_timeout = int(whatweb_cfg.get("open_timeout_seconds", 15) or 15)
        self.whatweb_read_timeout = int(whatweb_cfg.get("read_timeout_seconds", 30) or 30)
        self.whatweb_max_threads = int(whatweb_cfg.get("max_threads", 1) or 1)
        self.nmap_profiles = (
            set()
            if self.full_power
            else self._string_set(nmap_cfg.get("profiles", ["network_vulnerability_scan"]))
        )
        self.nuclei_profiles = (
            set()
            if self.full_power
            else self._string_set(nuclei_cfg.get("profiles", ["vulnerability_scan"]))
        )
        self.nmap_profile_timeouts = (
            {} if self.full_power else self._int_map(nmap_cfg.get("profile_timeouts", {}), minimum=0)
        )
        self.nuclei_profile_timeouts = (
            {} if self.full_power else self._int_map(nuclei_cfg.get("profile_timeouts", {}), minimum=0)
        )
        self.ffuf_timeout = int(1800 if self.full_power else (ffuf_cfg.get("timeout_seconds", 600) or 600))
        self.ffuf_threads = int(50 if self.full_power else (ffuf_cfg.get("threads", 20) or 20))
        self.ffuf_rate = int(100 if self.full_power else (ffuf_cfg.get("rate", 35) or 35))
        requested_ffuf_max_words = int(0 if self.full_power else (ffuf_cfg.get("max_words", self.DEFAULT_MIN_WORDLIST_ENTRIES) or 0))
        self.ffuf_max_words = (
            0
            if requested_ffuf_max_words == 0
            else max(self.DEFAULT_MIN_WORDLIST_ENTRIES, requested_ffuf_max_words)
        )
        self.whatweb_timeout = int(whatweb_cfg.get("timeout_seconds", 90) or 90)
        self.subfinder_timeout = int(subfinder_cfg.get("timeout_seconds", 180) or 180)
        self.wafw00f_timeout = int(300 if self.full_power else (wafw00f_cfg.get("timeout_seconds", 180) or 180))
        self.zap_host = str(zap_cfg.get("host", "127.0.0.1") or "127.0.0.1")
        self.zap_port = int(zap_cfg.get("port", 8090) or 8090)
        self.zap_api_url = str(zap_cfg.get("api_url") or f"http://{self.zap_host}:{self.zap_port}").rstrip("/")
        self.zap_api_key = str(zap_cfg.get("api_key", "") or "")
        self.zap_mode = str(
            getattr(args, "zap_mode", None)
            or ("active" if self.full_power else zap_cfg.get("mode", "baseline"))
            or "baseline"
        ).lower()
        if self.zap_mode not in {"passive", "baseline", "active"}:
            self.zap_mode = "baseline"
        self.zap_start_daemon = self._bool_config(zap_cfg.get("start_daemon", True))
        self.zap_shutdown_after_scan = self._bool_config(zap_cfg.get("shutdown_after_scan", True))
        self.zap_timeout = self._timeout_value(None if self.full_power else zap_cfg.get("timeout_seconds", 0), 0)
        self.zap_startup_timeout = int(180 if self.full_power else (zap_cfg.get("startup_timeout_seconds", 90) or 90))
        self.zap_spider_timeout = self._timeout_value(
            None if self.full_power else zap_cfg.get("spider_timeout_seconds", 0),
            0,
        )
        self.zap_passive_timeout = self._timeout_value(
            None if self.full_power else zap_cfg.get("passive_timeout_seconds", 0),
            0,
        )
        self.zap_active_timeout = self._timeout_value(
            None if self.full_power else zap_cfg.get("active_timeout_seconds", 0),
            0,
        )
        self.zap_max_seed_urls = int(500 if self.full_power else (zap_cfg.get("max_seed_urls", 160) or 160))
        self.zap_max_alerts = int(1000 if self.full_power else (zap_cfg.get("max_alerts", 500) or 500))
        self.zap_max_children = int(120 if self.full_power else (zap_cfg.get("max_children", 40) or 40))
        self.module_timeout = self._timeout_value(
            args.module_timeout,
            0 if self.full_power else scan_cfg.get("module_timeout_seconds", 0),
        )
        self.skip_external = bool(args.skip_external or self.policy.skip_external)
        self.allow_cloud_ssrf = self.policy.allow_cloud_ssrf
        self.config_data = config_data
        knowledge_cfg = config_data.get("knowledge_base", {})
        if not isinstance(knowledge_cfg, dict):
            knowledge_cfg = {}
        self.knowledge_enabled = self._bool_config(knowledge_cfg.get("enabled", True))
        self.knowledge_path = self._path_config(knowledge_cfg.get("path"), KNOWLEDGE_FILE)
        self.knowledge_min_score = float(knowledge_cfg.get("min_score", 5.0) or 5.0)
        reporting_cfg = config_data.get("reporting", {}) if isinstance(config_data.get("reporting"), dict) else {}
        self.report_min_severity = "Info" if self.full_power else normalize_severity(reporting_cfg.get("min_severity", "Low"))
        self.include_recon_info_findings = (
            True if self.full_power else self._bool_config(reporting_cfg.get("include_recon_info_findings", False))
        )
        self.include_pipeline_findings = (
            True if self.full_power else self._bool_config(reporting_cfg.get("include_pipeline_findings", False))
        )
        technical_cfg = reporting_cfg.get("technical_detail", {})
        self.technical_detail = TechnicalDetailOptions.from_config(technical_cfg, BASE_DIR, REPORTS_DIR)
        self.audit_id_argument = str(getattr(args, "audit_id", "") or "").strip()
        self.audit_id_automatic = False

    def _load_yaml(self, path: Path) -> dict[str, Any]:
        if not path.exists() or not YAML_AVAILABLE:
            return {}
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            Console.warn(f"config.yaml ignored: {exc}")
            return {}

    def _bool_config(self, value: Any) -> bool:
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
        return bool(value)

    def _timeout_value(self, value: Any, default: Any = 0) -> int:
        raw = default if value in (None, "") else value
        try:
            return max(0, int(raw))
        except (TypeError, ValueError):
            try:
                return max(0, int(default or 0))
            except (TypeError, ValueError):
                return 0

    def _int_map(self, value: Any, minimum: int = 1) -> dict[str, int]:
        if not isinstance(value, dict):
            return {}
        out: dict[str, int] = {}
        for key, raw in value.items():
            try:
                out[str(key).strip().lower()] = max(minimum, int(raw))
            except (TypeError, ValueError):
                continue
        return out

    def _string_set(self, value: Any) -> set[str]:
        if isinstance(value, str):
            value = [item.strip() for item in value.split(",")]
        if not isinstance(value, list):
            return set()
        return {str(item).strip().lower() for item in value if str(item).strip()}

    def _path_config(self, value: Any, default: Path) -> Path:
        if not value:
            return default
        path = Path(str(value))
        if not path.is_absolute():
            path = BASE_DIR / path
        return path

    def module_test_budget(self, module_name: str) -> int:
        normalized = str(module_name or "").strip().lower()
        budget = max(1, int(self.module_test_budgets.get(normalized, self.max_tests_per_module)))
        if self.policy.profile == "deep" and normalized in self.WORDLIST_HEAVY_MODULES:
            budget = max(self.DEFAULT_MIN_WORDLIST_TESTS, budget)
        return budget

    def module_timeout_for(self, module_name: str) -> int:
        normalized = str(module_name or "").strip().lower()
        return max(0, int(self.module_timeout_overrides.get(normalized, self.module_timeout)))

    def apply_module_throttle(self, module_name: str, limits: ScanLimits) -> dict[str, Any]:
        normalized = str(module_name or "").strip().lower()
        if normalized in self.PAYLOAD_JITTER_MODULES:
            limits.delay_seconds = self.payload_delay_seconds
            limits.jitter_min_seconds = self.payload_jitter_min_seconds
            limits.jitter_max_seconds = self.payload_jitter_max_seconds
            limits.throttle_batch_size = self.payload_throttle_batch_size
            mode = "payload"
        elif normalized in self.ROUTE_JITTER_MODULES:
            limits.delay_seconds = self.route_delay_seconds
            limits.jitter_min_seconds = self.route_jitter_min_seconds
            limits.jitter_max_seconds = self.route_jitter_max_seconds
            limits.throttle_batch_size = self.route_throttle_batch_size
            mode = "rutas"
        else:
            limits.delay_seconds = self.delay_seconds
            limits.jitter_min_seconds = self.jitter_min_seconds
            limits.jitter_max_seconds = self.jitter_max_seconds
            limits.throttle_batch_size = self.throttle_batch_size
            mode = "general"
        override = self.module_throttle_overrides.get(normalized, {})
        if isinstance(override, dict):
            limits.delay_seconds = float(override.get("delay_seconds", limits.delay_seconds) or 0.0)
            limits.jitter_min_seconds = float(override.get("jitter_min_seconds", limits.jitter_min_seconds) or 0.0)
            limits.jitter_max_seconds = float(override.get("jitter_max_seconds", limits.jitter_max_seconds) or 0.0)
            limits.throttle_batch_size = int(override.get("throttle_batch_size", limits.throttle_batch_size) or 1)
            if limits.jitter_max_seconds < limits.jitter_min_seconds:
                limits.jitter_max_seconds = limits.jitter_min_seconds
            mode = f"{mode}/ajuste-{normalized}"
        return {
            "mode": mode,
            "batch_size": max(1, int(limits.throttle_batch_size or 1)),
            "delay": round(float(limits.delay_seconds or 0.0), 3),
            "jitter_min": round(float(limits.jitter_min_seconds or 0.0), 3),
            "jitter_max": round(float(limits.jitter_max_seconds or 0.0), 3),
        }

    def external_profile_enabled(self, tool: str, profile: str) -> bool:
        selected = self.nmap_profiles if tool == "nmap" else self.nuclei_profiles
        return not selected or profile.lower() in selected

    def external_profile_timeout(self, tool: str, profile: str, fallback: int) -> int:
        timeouts = self.nmap_profile_timeouts if tool == "nmap" else self.nuclei_profile_timeouts
        try:
            return max(0, int(timeouts.get(profile.lower(), fallback)))
        except (TypeError, ValueError):
            return max(0, int(fallback or 0))

    def ensure_audit_id(self) -> str:
        if not self.technical_detail.enabled:
            return ""
        context_path = self.technical_detail.output_dir / ".state" / "audit_context.json"
        legacy_context_path = self.technical_detail.output_dir / "audit_context.json"
        explicit_candidate = (
            self.audit_id_argument
            or self.technical_detail.audit_id
            or os.environ.get("SCAN_TITAN_AUDIT_ID", "")
        )
        saved_candidate = ""
        readable_context_path = context_path if context_path.exists() else legacy_context_path
        if readable_context_path.exists():
            try:
                saved = json.loads(readable_context_path.read_text(encoding="utf-8"))
                saved_candidate = str(saved.get("audit_id") or "") if isinstance(saved, dict) else ""
            except Exception:
                saved_candidate = ""
        candidate = str(explicit_candidate or "").strip()
        self.audit_id_automatic = not bool(candidate)
        if not candidate:
            normalized_saved = re.sub(r"[^A-Za-z0-9]+", "", saved_candidate).upper()[:64]
            if re.fullmatch(r"ST0[A-Z0-9]{1,61}", normalized_saved):
                candidate = normalized_saved
            else:
                candidate = f"ST0{datetime.now().strftime('%y%m%d%H%M')}{uuid.uuid4().hex[:4].upper()}"
        normalized = re.sub(r"[^A-Za-z0-9]+", "", candidate).upper()[:64]
        if not normalized.startswith("ST0"):
            normalized = f"ST0{normalized}"[:64]
        if len(normalized) < 4:
            normalized = f"ST0{datetime.now().strftime('%y%m%d%H%M')}{uuid.uuid4().hex[:4].upper()}"
        self.technical_detail.audit_id = normalized
        context_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = context_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "schema": "scan_titan_audit_context_v2",
                    "audit_id": normalized,
                    "automatic": self.audit_id_automatic,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        temporary.replace(context_path)
        legacy_context_path.unlink(missing_ok=True)
        return normalized


class TargetLoader:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self._whatweb_official_cache: dict[str, bool] = {}

    def load(self) -> list[Target]:
        raw = [self.config.target] if self.config.target else []
        if not raw:
            raw.extend(self._read_target_file(self.config.targets_file))
            raw.extend(self._read_targets_dir(self.config.targets_dir))
        targets: list[Target] = []
        seen: set[str] = set()
        for item in raw:
            normalized = self._normalize(str(item))
            if not normalized:
                continue
            key = normalized.url.lower()
            if key in seen:
                continue
            seen.add(key)
            targets.append(normalized)
        return targets

    def _read_target_file(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        try:
            return [
                line.strip()
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        except Exception as exc:
            Console.warn(f"Could not read {path}: {exc}")
            return []

    def _read_targets_dir(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        out: list[str] = []
        for file_path in sorted(path.rglob("*")):
            if file_path.is_file() and file_path.suffix.lower() in {".txt", ".lst", ".list", ".csv"}:
                out.extend(self._read_target_file(file_path))
        return out

    def _normalize(self, raw: str) -> Target | None:
        raw = raw.strip()
        if not raw:
            return None
        if not raw.startswith(("http://", "https://")):
            host_candidate = raw.split("/", 1)[0].split(":", 1)[0].strip("[]")
            scheme = "http://" if self._is_ip(host_candidate) else "https://"
            raw = scheme + raw
        try:
            parsed = urllib.parse.urlparse(raw)
            host = parsed.hostname or ""
            if not host:
                raise ValueError("missing host")
            clean_url = parsed._replace(fragment="").geturl()
            is_ip = self._is_ip(host)
            ip = host if is_ip else socket.gethostbyname(host)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return Target(raw=raw, url=clean_url, host=host, ip=ip, scheme=parsed.scheme, port=port, is_ip=is_ip)
        except Exception as exc:
            Console.error(f"Invalid target {raw}: {exc}")
            return None

    def _is_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


class WordlistLoader:
    MIN_EFFECTIVE_ENTRIES = 10_000
    FILES = {
        "403bypass": "403bypass.txt",
        "command_injection": "command_injection.txt",
        "lfi": "lfi.txt",
        "passwords": "passwords.txt",
        "rutas": "rutas.txt",
        "sqli": "sqli.txt",
        "ssrf": "ssrf.txt",
        "ssti": "ssti.txt",
        "subdomains": "subdomains.txt",
        "users": "users.txt",
        "xss": "xss.txt",
        "xss_payloads": "xss_payloads.txt",
    }
    ALIASES = {
        "directories": "rutas",
        "directory": "rutas",
        "paths": "rutas",
        "cmdi": "command_injection",
        "command": "command_injection",
        "xss_payload": "xss_payloads",
    }
    LFI_TOKEN_MAP = {
        "{TRAV}": "../",
        "{BTRAV}": "..\\",
        "{ENC_TRAV}": "..%2f",
        "{ENC_BTRAV}": "..%5c",
        "{DENC_TRAV}": "%252e%252e%252f",
        "{LNX_A}": "/etc/passwd",
        "{LNX_B}": "/etc/shadow",
        "{LNX_C}": "/etc/hosts",
        "{LNX_D}": "/etc/issue",
        "{LNX_E}": "/etc/resolv.conf",
        "{REL_A}": "etc/passwd",
        "{REL_B}": "etc/shadow",
        "{REL_C}": "etc/hosts",
        "{REL_D}": "etc/issue",
        "{REL_E}": "etc/resolv.conf",
        "{REL_PROC_A}": "proc/self/environ",
        "{REL_PROC_B}": "proc/self/cmdline",
        "{REL_PROC_C}": "proc/version",
        "{REL_WIN_A}": "windows/win.ini",
        "{REL_WIN_B}": "boot.ini",
        "{REL_WIN_C}": "windows/system32/drivers/etc/hosts",
        "{PROC_A}": "/proc/self/environ",
        "{PROC_B}": "/proc/self/cmdline",
        "{PROC_C}": "/proc/version",
        "{PHP_A}": "php://filter/convert.base64-encode/resource=",
        "{PHP_B}": "php://input",
        "{PHP_C}": "expect://id",
        "{APP_ENV}": ".env",
        "{APP_WEB}": "web.config",
        "{APP_WP}": "wp-config.php",
        "{APP_CFG}": "config.php",
        "{APP_PROPS}": "application.properties",
        "{APP_YML}": "application.yml",
        "{APP_JSON}": "appsettings.json",
        "{APP_XML}": "WEB-INF/web.xml",
        "{WIN_A}": "C:\\Windows\\win.ini",
        "{WIN_B}": "C:\\boot.ini",
        "{WIN_C}": "C:\\Windows\\System32\\drivers\\etc\\hosts",
    }

    def __init__(self, root: Path, max_entries: int) -> None:
        self.root = root
        self.max_entries = max_entries

    def load(self) -> dict[str, list[str]]:
        data: dict[str, list[str]] = {}
        for key, filename in self.FILES.items():
            data[key] = self._load_file(self.root / filename, key)
            Console.step(f"wordlist {key:<10}: {len(data[key])} entries")
        for path in sorted(self.root.glob("*.txt")):
            key = path.stem.strip().lower().replace("-", "_")
            if key not in data:
                data[key] = self._load_file(path, key)
                Console.step(f"wordlist {key:<10}: {len(data[key])} entries")
        for alias, canonical in self.ALIASES.items():
            if canonical in data and alias not in data:
                data[alias] = data[canonical]
        return data

    def _load_file(self, path: Path, key: str = "") -> list[str]:
        if not path.exists():
            return []
        values: list[str] = []
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    clean = re.sub(r"[\x00-\x1f\x7f]", "", line).strip()
                    if clean and not clean.startswith("#"):
                        values.append(self._decode_wordlist_entry(key, clean))
                    if self.max_entries > 0 and len(values) >= self.max_entries:
                        break
        except Exception as exc:
            Console.warn(f"Wordlist omitida {path}: {exc}")
        values = self._dedupe(values)
        values = self._ensure_effective_minimum(key, values)
        if self.max_entries > 0:
            values = values[: self.max_entries]
        return values

    def _decode_wordlist_entry(self, key: str, value: str) -> str:
        if key != "lfi":
            return value
        decoded = value
        for token, replacement in self.LFI_TOKEN_MAP.items():
            decoded = decoded.replace(token, replacement)
        depth_match = re.search(r"\{DEPTH:(\d+)\}", decoded)
        if depth_match:
            depth = max(1, min(int(depth_match.group(1)), 12))
            decoded = decoded.replace(depth_match.group(0), "../" * depth)
        bdepth_match = re.search(r"\{BDEPTH:(\d+)\}", decoded)
        if bdepth_match:
            depth = max(1, min(int(bdepth_match.group(1)), 12))
            decoded = decoded.replace(bdepth_match.group(0), "..\\" * depth)
        return decoded

    def _dedupe(self, values: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for value in values:
            clean = str(value or "").strip()
            key = clean.casefold()
            if clean and key not in seen:
                seen.add(key)
                out.append(clean)
        return out

    def _ensure_effective_minimum(self, key: str, values: list[str]) -> list[str]:
        if self.max_entries > 0 and self.max_entries < self.MIN_EFFECTIVE_ENTRIES:
            target_size = self.max_entries
        else:
            target_size = self.MIN_EFFECTIVE_ENTRIES
        if len(values) >= target_size:
            return values
        out = list(values)
        seen = {item.casefold() for item in out}

        def add(candidate: str) -> bool:
            clean = str(candidate or "").strip()
            if not clean or len(clean) > 260:
                return len(out) >= target_size
            dedupe_key = clean.casefold()
            if dedupe_key not in seen:
                seen.add(dedupe_key)
                out.append(clean)
            return len(out) >= target_size

        for candidate in self._generated_entries_for(key, values):
            if add(candidate):
                break
        seed_pool = values or [key]
        counter = 0
        while len(out) < target_size:
            seed = seed_pool[counter % len(seed_pool)]
            suffix = f"{counter:04d}"
            if key == "subdomains":
                candidate = f"{seed}-{suffix}"
            elif key == "users":
                candidate = f"{seed}{suffix}"
            elif key == "passwords":
                candidate = f"{seed}{suffix}!"
            elif key == "rutas":
                candidate = f"{str(seed).strip('/')}-{suffix}/"
            else:
                candidate = f"{seed}/*scan_titan_{suffix}*/"
            add(candidate)
            counter += 1
        return out

    def _generated_entries_for(self, key: str, values: list[str]) -> list[str]:
        generators = {
            "403bypass": self._generate_403_bypass,
            "command_injection": self._generate_command_injection,
            "lfi": self._generate_lfi,
            "sqli": self._generate_sqli,
            "ssrf": self._generate_ssrf,
            "ssti": self._generate_ssti,
            "subdomains": self._generate_subdomains,
            "users": self._generate_users,
            "xss": self._generate_xss,
            "xss_payloads": self._generate_xss,
        }
        generator = generators.get(key)
        return generator(values) if generator else []

    def _encoded_variants(self, value: str) -> list[str]:
        quoted = urllib.parse.quote(value, safe="")
        partial = urllib.parse.quote(value, safe="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        return [
            value,
            partial,
            quoted,
            quoted.replace("%", "%25"),
            value.replace(" ", "/**/"),
            value.replace(" ", "%09"),
            value.replace(" ", "%0a"),
            value.replace("/", "%2f"),
        ]

    def _generate_sqli(self, values: list[str]) -> list[str]:
        out: list[str] = []
        bases = values[:800] or ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
        for seed in bases:
            out.extend(self._encoded_variants(seed))
        prefixes = ["", "'", "\"", "1'", "1\"", "')", "\")", "%27", "%22"]
        operators = [" OR ", " AND ", "/**/OR/**/", "/**/AND/**/", "%20OR%20", "%09OR%09"]
        conditions = ["1=1", "2=2", "'a'='a'", "\"a\"=\"a\"", "1 LIKE 1", "1 IN (1)", "NOT 1=2"]
        tails = ["--", "-- -", "#", "/*", "%23", "%2d%2d", ";--", ")--"]
        for prefix in prefixes:
            for operator in operators:
                for condition in conditions:
                    for tail in tails:
                        out.append(f"{prefix}{operator}{condition}{tail}")
        for columns in range(1, 21):
            nulls = ",".join(["NULL"] * columns)
            out.extend(
                [
                    f"' UNION SELECT {nulls}-- -",
                    f"') UNION SELECT {nulls}-- -",
                    f"\" UNION SELECT {nulls}-- -",
                    f"' ORDER BY {columns}-- -",
                    f"\") ORDER BY {columns}-- -",
                ]
            )
        return out

    def _generate_lfi(self, _values: list[str]) -> list[str]:
        files = [
            "/etc/passwd",
            "/etc/hosts",
            "/etc/issue",
            "/etc/resolv.conf",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/version",
            "windows/win.ini",
            "boot.ini",
            "windows/system32/drivers/etc/hosts",
            ".env",
            "config.php",
            "wp-config.php",
            "web.config",
            "application.properties",
            "application.yml",
            "appsettings.json",
            "WEB-INF/web.xml",
        ]
        prefixes = ["../", "..\\", "....//", "..%2f", "..%5c", "%2e%2e%2f", "%252e%252e%252f"]
        suffixes = ["", "%00", "%2500", ".", "%0a", "%0d%0a", "?scan_titan=1", "#"]
        wrappers = ["{trav}{file}", "/{trav}{file}", "file:///{trav}{file}", "php://filter/convert.base64-encode/resource={trav}{file}"]
        out: list[str] = []
        for depth in range(1, 13):
            for prefix in prefixes:
                traversal = prefix * depth
                for file_name in files:
                    clean_file = file_name.lstrip("/")
                    for wrapper in wrappers:
                        candidate = wrapper.format(trav=traversal, file=clean_file)
                        for suffix in suffixes:
                            out.append(candidate + suffix)
        return out

    def _generate_xss(self, values: list[str]) -> list[str]:
        out: list[str] = []
        seeds = values[:700] or [
            "<script>alert(1)</script>",
            "\"><svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
        ]
        for seed in seeds:
            out.extend(self._encoded_variants(seed))
        tags = ["svg", "img", "body", "details", "input", "iframe", "video", "audio", "marquee", "math"]
        events = ["onload", "onerror", "onclick", "onmouseover", "onfocus", "ontoggle", "onbegin", "onanimationstart"]
        calls = ["alert(1)", "confirm(1)", "prompt(1)", "window['alert'](1)", "top['ale'+'rt'](1)"]
        wrappers = ["<{tag} {event}={call}>", "\"><{tag} {event}={call}>", "'><{tag} {event}={call}>", "<{tag}/{event}={call}>"]
        for tag in tags:
            for event in events:
                for call in calls:
                    for wrapper in wrappers:
                        payload = wrapper.format(tag=tag, event=event, call=call)
                        out.extend(self._encoded_variants(payload))
        return out

    def _generate_ssti(self, values: list[str]) -> list[str]:
        out: list[str] = []
        seeds = values[:300]
        for seed in seeds:
            out.extend(self._encoded_variants(seed))
        expressions = ["7*7", "6*7", "9*9"]
        wrappers = [
            "{{{expr}}}",
            "${{{expr}}}",
            "<%={expr}%>",
            "#{{{expr}}}",
            "*{{{expr}}}",
            "'{{{expr}}}'",
            "\"{{{expr}}}\"",
            "{{{{{expr}}}}}",
            "${{{{{expr}}}}}",
            "{{% print({expr}) %}}",
        ]
        prefixes = ["", "scan_titan", "../", "'\"", "%27", "%22", "<!--", "${", "{{"]
        suffixes = ["", "}}", "}", "-->", "%00", "%0a", "scan_titan", "/*"]
        for expr in expressions:
            for wrapper in wrappers:
                base = wrapper.format(expr=expr)
                for prefix in prefixes:
                    for suffix in suffixes:
                        out.extend(self._encoded_variants(prefix + base + suffix))
        return out

    def _generate_ssrf(self, values: list[str]) -> list[str]:
        out: list[str] = []
        seeds = values[:300]
        for seed in seeds:
            out.extend(self._encoded_variants(seed))
        hosts = [
            "127.0.0.1",
            "localhost",
            "[::1]",
            "0.0.0.0",
            "169.254.169.254",
            "metadata.google.internal",
            "kubernetes.default.svc",
        ]
        hosts.extend(f"127.0.0.{index}" for index in range(1, 256))
        hosts.extend(f"10.0.{a}.{b}" for a in range(0, 8) for b in range(1, 16))
        hosts.extend(f"192.168.{a}.{b}" for a in range(0, 8) for b in range(1, 16))
        ports = [80, 443, 8000, 8080, 8081, 8443, 9000, 9090, 9200, 2375, 2379, 5000, 5432, 6379, 27017]
        paths = ["/", "/admin", "/health", "/metrics", "/server-status", "/latest/meta-data/", "/metadata/v1/", "/version"]
        for scheme in ["http", "https"]:
            for host in hosts:
                for port in ports:
                    for path in paths:
                        out.append(f"{scheme}://{host}:{port}{path}")
        return out

    def _generate_command_injection(self, values: list[str]) -> list[str]:
        out: list[str] = []
        seeds = values[:300]
        for seed in seeds:
            out.extend(self._encoded_variants(seed))
        commands = [
            "echo scan_titan_marker",
            "id",
            "whoami",
            "uname -a",
            "cat /etc/hosts",
            "type C:\\Windows\\win.ini",
            "ipconfig",
            "dir",
        ]
        separators = [";", "&&", "||", "|", "%26%26", "%7c", "%3b", "`", "$(", "\n", "%0a", "&"]
        wrappers = ["{sep}{cmd}", "test{sep}{cmd}", "\"{sep}{cmd}", "'{sep}{cmd}", "1{sep}{cmd}{sep}", "$({cmd})", "`{cmd}`"]
        for separator in separators:
            for command in commands:
                for wrapper in wrappers:
                    payload = wrapper.format(sep=separator, cmd=command)
                    out.extend(self._encoded_variants(payload))
        return out

    def _generate_403_bypass(self, values: list[str]) -> list[str]:
        out = list(values[:600])
        base_paths = ["admin", "api", "login", "dashboard", "server-status", ".env", ".git/config", "config.php", "debug", "metrics"]
        prefixes = ["", "/", "//", "/./", "/../", "%2f", "%252f", ";", "%3b", "%20", "%09", "%00"]
        suffixes = ["", "/", "/.", "..;/", ";", "%3b", "%20", "%09", "?", "??", "#", "%23", ".json", ".bak"]
        for path in base_paths:
            for prefix in prefixes:
                for suffix in suffixes:
                    candidate = f"{prefix}{path}{suffix}"
                    out.extend([candidate, urllib.parse.quote(candidate, safe="/.%")])
        return out

    def _generate_subdomains(self, values: list[str]) -> list[str]:
        out = list(values[:500])
        bases = values[:300] or ["www", "api", "admin", "portal", "dev", "test", "qa", "vpn", "mail"]
        envs = ["dev", "qa", "uat", "stage", "stg", "pre", "prod", "int", "corp", "cloud", "app", "web", "api"]
        regions = ["gt", "sv", "hn", "ni", "cr", "pa", "us", "mx", "latam"]
        for base in bases:
            clean = re.sub(r"[^a-zA-Z0-9-]", "", base).lower() or "host"
            for env in envs:
                for region in regions:
                    out.extend([f"{env}-{clean}", f"{clean}-{env}", f"{clean}-{region}", f"{env}-{clean}-{region}"])
            for index in range(0, 250):
                out.append(f"{clean}{index:02d}")
        return out

    def _generate_users(self, values: list[str]) -> list[str]:
        out = list(values[:600])
        bases = values[:400] or ["admin", "administrator", "root", "user", "test", "auditor", "soporte", "operador"]
        suffixes = ["", "1", "01", "123", "2024", "2025", "2026", ".admin", "_admin", ".test", "_test", "-dev"]
        domains = ["", "@local", "@example.com", "@corp.local", "@domain.local"]
        for base in bases:
            clean = re.sub(r"[^A-Za-z0-9._-]", "", base) or "user"
            for suffix in suffixes:
                for domain in domains:
                    out.append(f"{clean}{suffix}{domain}")
            for index in range(0, 120):
                out.append(f"{clean}{index:03d}")
        return out


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema": 3, "findings": {}}
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict) and isinstance(data.get("findings"), dict):
                data["schema"] = 3
                for record in data["findings"].values():
                    if not isinstance(record, dict):
                        continue
                    if record.get("owasp") or record.get("cwe") or normalize_severity(record.get("severity", "Info")) != "Info":
                        record["owasp"] = normalize_owasp_2025(
                            record.get("owasp", ""),
                            cwe=record.get("cwe", ""),
                            category=record.get("category", ""),
                            title=record.get("title", ""),
                            evidence=record.get("last_evidence", ""),
                        )
                data["findings"] = self._migrate_records(data["findings"])
                return data
        except Exception as exc:
            Console.warn(f"State ignored: {exc}")
        return {"schema": 3, "findings": {}}

    def _migrate_records(self, records: dict[str, Any]) -> dict[str, Any]:
        migrated: dict[str, dict[str, Any]] = {}
        for raw_record in records.values():
            if not isinstance(raw_record, dict):
                continue
            record = dict(raw_record)
            asset = str(record.get("asset") or record.get("target") or "").strip()
            record["asset"] = asset
            record["canonical_id"] = str(record.get("canonical_id") or canonical_vulnerability_id(record))
            sources = record.get("correlated_sources") or [record.get("source")]
            if isinstance(sources, str):
                sources = [item.strip() for item in sources.split(",")]
            record["correlated_sources"] = list(dict.fromkeys(str(item) for item in sources if str(item).strip()))
            fingerprint = vulnerability_occurrence_key(record, asset)
            record["fingerprint"] = fingerprint
            current = migrated.get(fingerprint)
            if current is None:
                migrated[fingerprint] = record
                continue
            current["first_seen"] = min(
                value for value in [str(current.get("first_seen") or ""), str(record.get("first_seen") or "")] if value
            ) if current.get("first_seen") or record.get("first_seen") else ""
            current["last_seen"] = max(
                value for value in [str(current.get("last_seen") or ""), str(record.get("last_seen") or "")] if value
            ) if current.get("last_seen") or record.get("last_seen") else ""
            current["occurrences"] = max(int(current.get("occurrences") or 1), int(record.get("occurrences") or 1))
            current["correlated_sources"] = list(
                dict.fromkeys([*(current.get("correlated_sources") or []), *(record.get("correlated_sources") or [])])
            )
            if SEVERITY_ORDER.get(normalize_severity(record.get("severity", "Info")), 99) < SEVERITY_ORDER.get(
                normalize_severity(current.get("severity", "Info")), 99
            ):
                current["severity"] = normalize_severity(record.get("severity", "Info"))
            if len(str(record.get("last_evidence") or "")) > len(str(current.get("last_evidence") or "")):
                current["last_evidence"] = record.get("last_evidence")
        return migrated

    def enrich(self, findings: list[Finding], scanned_target: str, timestamp: str) -> list[Finding]:
        for finding in findings:
            finding.refresh_identity(finding.asset or scanned_target)
        unique = {finding.fingerprint: finding for finding in findings}
        records = self.data.setdefault("findings", {})
        for fingerprint, finding in unique.items():
            record = records.get(fingerprint, {})
            previous_state = str(record.get("state") or "").upper()
            is_regression = previous_state == "NOT_SEEN"
            first_seen = record.get("first_seen") or timestamp
            occurrences = int(record.get("occurrences") or 0) + 1
            finding.first_seen = first_seen
            finding.last_seen = timestamp
            finding.occurrences = occurrences
            finding.state = "ACTIVE"
            finding.evidence_artifact = finding.evidence_artifact or record.get("evidence_artifact", "")
            finding.console_artifact = finding.console_artifact or record.get("console_artifact", "")
            finding.browser_artifact = finding.browser_artifact or record.get("browser_artifact", "")
            records[fingerprint] = {
                "target": finding.target,
                "asset": finding.asset or scanned_target,
                "canonical_id": finding.canonical_id,
                "correlated_sources": finding.correlated_sources,
                "category": finding.category,
                "severity": finding.severity,
                "title": finding.title,
                "fingerprint": fingerprint,
                "first_seen": first_seen,
                "last_seen": timestamp,
                "occurrences": occurrences,
                "state": "ACTIVE",
                "previous_state": previous_state or "NEW",
                "state_changed_at": timestamp if previous_state != "ACTIVE" else record.get("state_changed_at", ""),
                "reappeared_at": timestamp if is_regression else record.get("reappeared_at", ""),
                "regression_count": int(record.get("regression_count") or 0) + (1 if is_regression else 0),
                "last_url": finding.url,
                "last_evidence": clean_text(finding.evidence, 1000),
                "confidence": finding.confidence,
                "evidence_strength": finding.evidence_strength,
                "false_positive_risk": finding.false_positive_risk,
                "cwe": finding.cwe,
                "owasp": finding.owasp,
                "cvss": finding.cvss,
                "impact": finding.impact,
                "remediation": finding.remediation,
                "recommendation": finding.recommendation,
                "manual_command": finding.manual_command,
                "evidence_artifact": finding.evidence_artifact or record.get("evidence_artifact", ""),
                "console_artifact": finding.console_artifact or record.get("console_artifact", ""),
                "browser_artifact": finding.browser_artifact or record.get("browser_artifact", ""),
                "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        for fingerprint, record in records.items():
            if record.get("target") == scanned_target and fingerprint not in unique:
                if record.get("state") == "ACTIVE":
                    record["previous_state"] = "ACTIVE"
                    record["state"] = "NOT_SEEN"
                    record["state_changed_at"] = timestamp
        return sorted(
            unique.values(),
            key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.category, item.title),
        )

    def active_records(self) -> list[dict[str, Any]]:
        return sorted(
            [r for r in self.data.get("findings", {}).values() if r.get("state") == "ACTIVE"],
            key=lambda r: (
                SEVERITY_ORDER.get(normalize_severity(r.get("severity", "Info")), 99),
                str(r.get("target", "")),
                str(r.get("title", "")),
            ),
        )

    def sync_artifacts(self, findings: list[Finding]) -> None:
        records = self.data.setdefault("findings", {})
        for finding in findings:
            record = records.get(finding.fingerprint)
            if not isinstance(record, dict):
                continue
            if finding.evidence_artifact:
                record["evidence_artifact"] = finding.evidence_artifact
            if finding.console_artifact:
                record["console_artifact"] = finding.console_artifact
            record["confidence"] = finding.confidence
            record["evidence_strength"] = finding.evidence_strength
            record["false_positive_risk"] = finding.false_positive_risk
            record["cwe"] = finding.cwe
            record["owasp"] = finding.owasp
            record["cvss"] = finding.cvss
            record["impact"] = finding.impact
            record["remediation"] = finding.remediation
            record["recommendation"] = finding.recommendation
            record["manual_command"] = finding.manual_command
            record["asset"] = finding.asset
            record["canonical_id"] = finding.canonical_id
            record["correlated_sources"] = finding.correlated_sources
            if finding.browser_artifact:
                record["browser_artifact"] = finding.browser_artifact

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2, ensure_ascii=False)
        tmp.replace(self.path)


class ReportWriter:
    def __init__(self, report_dir: Path, history_dir: Path) -> None:
        self.report_dir = report_dir
        self.history_dir = history_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.history_dir.mkdir(parents=True, exist_ok=True)

    def write_target_report(self, target: Target, findings: list[Finding], timestamp: str) -> Path:
        path = self.report_dir / f"{self._slug(target.display)}_{timestamp.split()[0]}.txt"
        counts = Counter(finding.severity for finding in findings)
        with path.open("w", encoding="utf-8") as handle:
            handle.write(f"{HEADER_SEPARATOR}\n")
            handle.write(f"  {SCAN_VERSION} - AUDITORIA INTEGRAL DE SEGURIDAD\n")
            handle.write(f"  Objetivo: {target.display}\n")
            handle.write(f"  Fecha:    {timestamp}\n")
            handle.write(f"  Total:    {len(findings)} hallazgos\n")
            handle.write(f"{HEADER_SEPARATOR}\n\n")
            handle.write("RESUMEN:\n")
            for severity in ("Critical", "High", "Medium", "Low", "Info"):
                handle.write(f"  {severity_label_es(severity):<10}: {counts.get(severity, 0)}\n")
            handle.write(f"\n{REPORT_SEPARATOR}\n\n")
            for index, finding in enumerate(findings, start=1):
                handle.write(
                    f"[{index:03d}] [{severity_label_es(finding.severity).upper():<8}] "
                    f"{translate_visible_text(finding.title)}\n"
                )
                for line in finding.report_lines():
                    handle.write(f"{line}\n")
                handle.write(f"{REPORT_SEPARATOR}\n")
        self.write_target_json_report(target, findings, timestamp)
        return path

    def write_target_json_report(self, target: Target, findings: list[Finding], timestamp: str) -> Path:
        path = self.report_dir / f"{self._slug(target.display)}_{timestamp.split()[0]}.json"
        counts = Counter(finding.severity for finding in findings)
        payload = {
            "schema": "scan_titan_target_report_v1",
            "scanner": SCAN_VERSION,
            "target": target.display,
            "url": target.url,
            "ip": target.ip,
            "date": timestamp,
            "summary": {severity: counts.get(severity, 0) for severity in ("Critical", "High", "Medium", "Low", "Info")},
            "total_findings": len(findings),
            "findings": [self._finding_to_dict(index, finding) for index, finding in enumerate(findings, start=1)],
        }
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        return path

    def _finding_to_dict(self, index: int, finding: Finding) -> dict[str, Any]:
        return {
            "index": index,
            "severity": finding.severity,
            "title": finding.title,
            "category": finding.category,
            "target": finding.target,
            "asset": finding.asset,
            "canonical_id": finding.canonical_id,
            "correlated_sources": finding.correlated_sources,
            "url": finding.url,
            "endpoint": finding.endpoint,
            "param": finding.param,
            "method": finding.method,
            "payload": finding.payload,
            "http": finding.status,
            "size": finding.size,
            "time": finding.elapsed,
            "evidence": finding.evidence,
            "source": finding.source,
            "confidence": finding.confidence,
            "evidence_strength": finding.evidence_strength,
            "false_positive_risk": finding.false_positive_risk,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            "cvss": finding.cvss,
            "impact": finding.impact,
            "remediation": finding.remediation or finding.recommendation,
            "manual_command": finding.manual_command,
            "first_seen": finding.first_seen,
            "last_seen": finding.last_seen,
            "occurrences": finding.occurrences,
            "state": finding.state,
            "fingerprint": finding.fingerprint,
            "evidence_artifact": finding.evidence_artifact,
            "console_artifact": finding.console_artifact,
            "browser_artifact": finding.browser_artifact,
            "details": finding.details,
        }

    def write_history(self, results: list[dict[str, Any]], timestamp: str) -> Path:
        path = self.history_dir / f"SCAN_TITAN_HISTORY_{timestamp.split()[0]}.txt"
        total = sum(len(item["findings"]) for item in results)
        counts: Counter[str] = Counter()
        for item in results:
            counts.update(f.severity for f in item["findings"])
        mode = "a" if path.exists() else "w"
        with path.open(mode, encoding="utf-8") as handle:
            handle.write("\n" + "#" * 72 + "\n")
            handle.write("  REPORTE HISTORICO DE AUDITORIA SCAN TITAN\n")
            handle.write(f"  Fecha de Sesion : {timestamp}\n")
            handle.write(f"  Objetivos       : {len(results)}\n")
            handle.write(f"  Total Hallazgos : {total}\n")
            handle.write("#" * 72 + "\n\n")
            for severity in ("Critical", "High", "Medium", "Low", "Info"):
                handle.write(f"  {severity_label_es(severity):<10}: {counts.get(severity, 0)}\n")
            handle.write("\n")
        return path

    def write_formal_report(self, results: list[dict[str, Any]], timestamp: str) -> Path:
        date_slug = timestamp.split()[0]
        output = self.report_dir / f"Formal_Audit_Report_{date_slug}.html"
        latest = self.report_dir / "Formal_Audit_Report_Latest.html"
        findings = self._flatten_findings(results)
        counts = Counter(finding.severity for finding in findings)
        targets = [item["target"] for item in results if item.get("target")]
        critical_high = counts.get("Critical", 0) + counts.get("High", 0)
        executive_note = (
            "La ejecución identificó hallazgos críticos o altos que requieren priorización inmediata."
            if critical_high
            else "La ejecución no identificó hallazgos críticos o altos en los resultados reportables."
        )
        page = [
            "<!doctype html><html lang='es'><head><meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width,initial-scale=1'>",
            f"<title>Scan Titan - Informe Formal {html.escape(date_slug)}</title>",
            self._formal_report_style(),
            "</head><body>",
            "<section class='cover'>",
            "<div class='brand'>SCAN TITAN</div>",
            "<h1>Informe Formal de Vulnerabilidades</h1>",
            "<p class='subtitle'>Reporte ejecutivo y técnico generado de forma zero-touch</p>",
            "<dl class='cover-meta'>",
            f"<div><dt>Fecha de ejecución</dt><dd>{html.escape(timestamp)}</dd></div>",
            f"<div><dt>Scanner</dt><dd>{html.escape(SCAN_VERSION)}</dd></div>",
            f"<div><dt>Objetivos evaluados</dt><dd>{len(targets)}</dd></div>",
            f"<div><dt>Hallazgos reportables</dt><dd>{len(findings)}</dd></div>",
            "</dl>",
            "</section>",
            "<main class='report'>",
            "<section class='panel'>",
            "<h2>Resumen Ejecutivo</h2>",
            f"<p>{html.escape(executive_note)}</p>",
            "<div class='kpis'>",
        ]
        for severity in ("Critical", "High", "Medium", "Low", "Info"):
            page.append(
                f"<article class='kpi sev-{severity.lower()}'>"
                f"<span>{html.escape(severity_label_es(severity))}</span><strong>{counts.get(severity, 0)}</strong>"
                "</article>"
            )
        page.extend(
            [
                "</div>",
                "</section>",
                "<section class='panel'>",
                "<h2>Alcance Evaluado</h2>",
                "<table><thead><tr><th>Objetivo</th><th>IP</th><th>URL Base</th><th>Duracion</th><th>Hallazgos</th></tr></thead><tbody>",
            ]
        )
        for item in results:
            target: Target = item["target"]
            target_findings = item.get("findings", [])
            page.append(
                "<tr>"
                f"<td>{html.escape(target.display)}</td>"
                f"<td>{html.escape(target.ip)}</td>"
                f"<td>{html.escape(target.url)}</td>"
                f"<td>{float(item.get('duration', 0.0)):.1f}s</td>"
                f"<td>{len(target_findings)}</td>"
                "</tr>"
            )
        page.extend(["</tbody></table>", "</section>"])
        page.append("<section class='panel page-break'><h2>Detalle de Hallazgos</h2>")
        if not findings:
            page.append("<p>No se encontraron vulnerabilidades reportables en esta ejecución.</p>")
        for index, finding in enumerate(findings, start=1):
            page.append(self._formal_finding_card(index, finding))
        page.extend(
            [
                "</section>",
                "<section class='panel'>",
                "<h2>Archivos Generados</h2>",
                "<ul>",
                "<li>Dashboard de vulnerabilidades: <code>Daily_vulns_report.html</code></li>",
                "<li>Matriz de reconocimiento: <code>Recon_Matrix.xlsx</code></li>",
                "<li>Dashboard de reconocimiento: <code>Recon_Dashboard.html</code></li>",
                "<li>Site Map de reconocimiento: <code>Recon_Sitemap.html</code></li>",
                "<li>Estado de deduplicación: <code>scan_titan_state.json</code></li>",
                "</ul>",
                "</section>",
                "</main></body></html>",
            ]
        )
        html_text = "\n".join(page)
        output.write_text(html_text, encoding="utf-8")
        latest.write_text(html_text, encoding="utf-8")
        return output

    def _flatten_findings(self, results: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        for item in results:
            for finding in item.get("findings", []) or []:
                if isinstance(finding, Finding):
                    findings.append(finding)
        return sorted(
            findings,
            key=lambda item: (
                SEVERITY_ORDER.get(item.severity, 99),
                str(item.target),
                str(item.title),
                str(item.url),
            ),
        )

    def _formal_finding_card(self, index: int, finding: Finding) -> str:
        evidence_href = self._artifact_href(finding.evidence_artifact)
        browser_href = self._artifact_href(finding.browser_artifact)
        rows = [
            ("ID", finding.canonical_id or finding.fingerprint[:16]),
            ("Severidad", finding.severity),
            ("CWE", finding.cwe),
            ("OWASP", finding.owasp),
            ("CVSS", finding.cvss),
            ("Confianza", finding.confidence),
            ("Fuerza de Evidencia", finding.evidence_strength),
            ("Riesgo de Falso Positivo", finding.false_positive_risk),
            ("First Seen", finding.first_seen),
            ("Last Seen", finding.last_seen),
            ("Ocurrencias", str(finding.occurrences)),
            ("Fuente", ", ".join(finding.correlated_sources or [finding.source])),
            ("URL", finding.url),
            ("Endpoint", finding.endpoint),
            ("Parámetro", finding.param),
            ("Método", finding.method),
            ("HTTP", finding.status),
            ("Tamaño", finding.size),
            ("Tiempo", finding.elapsed),
        ]
        meta = "".join(
            f"<div><dt>{html.escape(label)}</dt><dd>{html.escape(clean_text(value, 900))}</dd></div>"
            for label, value in rows
            if value not in ("", None)
        )
        artifacts = []
        if evidence_href:
            artifacts.append(f"<a href='{html.escape(evidence_href)}'>Tarjeta PNG de evidencia</a>")
        if browser_href:
            artifacts.append(f"<a href='{html.escape(browser_href)}'>Captura browser del hallazgo</a>")
        artifact_html = (
            "<div class='artifact-links'>" + " ".join(artifacts) + "</div>"
            if artifacts
            else ""
        )
        browser_preview = (
            f"<figure><img src='{html.escape(browser_href)}' alt='Browser evidence'><figcaption>Evidencia browser</figcaption></figure>"
            if browser_href
            else ""
        )
        return (
            f"<article class='finding sev-border-{finding.severity.lower()}'>"
            f"<h3>[{index:03d}] [{html.escape(finding.severity.upper())}] {html.escape(finding.title)}</h3>"
            f"<dl class='finding-grid'>{meta}</dl>"
            f"{self._formal_block('Payload', finding.payload)}"
            f"{self._formal_block('Evidencia Técnica', finding.evidence)}"
            f"{self._formal_block('Impacto', finding.impact)}"
            f"{self._formal_block('Remediación', finding.remediation or finding.recommendation)}"
            f"{self._formal_block('Comando de Validación Manual', finding.manual_command)}"
            f"{artifact_html}{browser_preview}"
            "</article>"
        )

    def _formal_block(self, title: str, value: str) -> str:
        if value in ("", None):
            return ""
        return (
            "<section class='finding-block'>"
            f"<h4>{html.escape(title)}</h4>"
            f"<pre>{html.escape(clean_text(value, 5000))}</pre>"
            "</section>"
        )

    def _artifact_href(self, value: str) -> str:
        if not value:
            return ""
        path = Path(str(value))
        try:
            if path.exists():
                return path.resolve().relative_to(self.report_dir.resolve()).as_posix()
        except Exception:
            pass
        try:
            if path.exists():
                return path.resolve().as_uri()
        except Exception:
            pass
        return ""

    def _formal_report_style(self) -> str:
        return """<style>
:root{--bg:#f5f7fb;--ink:#111827;--muted:#5b6678;--panel:#ffffff;--line:#d9e1ec;--navy:#0b1727;--blue:#1d4ed8;--critical:#991b1b;--high:#dc2626;--medium:#b45309;--low:#0369a1;--info:#475569}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 Segoe UI,Arial,sans-serif}code,pre{font-family:Consolas,monospace}.cover{min-height:100vh;background:linear-gradient(135deg,#06111f,#172554);color:white;padding:72px;display:flex;flex-direction:column;justify-content:center}.brand{font-size:15px;letter-spacing:.26em;font-weight:800;color:#67e8f9}.cover h1{font-size:58px;line-height:1.05;margin:18px 0 10px;max-width:880px}.subtitle{font-size:20px;color:#cbd5e1;margin:0 0 44px}.cover-meta{display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:14px;max-width:1050px}.cover-meta div,.kpi,.panel,.finding{border:1px solid var(--line);border-radius:10px;background:var(--panel)}.cover-meta div{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.2);padding:18px}.cover-meta dt,.finding-grid dt{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;font-weight:700}.cover-meta dd,.finding-grid dd{margin:5px 0 0;font-weight:700;overflow-wrap:anywhere}.report{max-width:1280px;margin:0 auto;padding:34px 28px}.panel{padding:24px;margin-bottom:22px;box-shadow:0 8px 24px rgba(15,23,42,.07)}h2{font-size:22px;margin:0 0 14px;color:var(--navy)}.kpis{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}.kpi{padding:16px}.kpi span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;font-weight:800}.kpi strong{display:block;font-size:32px;margin-top:4px}.sev-critical strong{color:var(--critical)}.sev-high strong{color:var(--high)}.sev-medium strong{color:var(--medium)}.sev-low strong{color:var(--low)}.sev-info strong{color:var(--info)}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid var(--line);padding:9px 10px;text-align:left;vertical-align:top}th{background:var(--navy);color:white}.finding{padding:22px;margin:18px 0;border-left-width:7px}.sev-border-critical{border-left-color:var(--critical)}.sev-border-high{border-left-color:var(--high)}.sev-border-medium{border-left-color:var(--medium)}.sev-border-low{border-left-color:var(--low)}.sev-border-info{border-left-color:var(--info)}.finding h3{margin:0 0 16px;font-size:19px}.finding-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:0 0 16px}.finding-grid div{background:#f8fafc;border:1px solid var(--line);border-radius:8px;padding:10px}.finding-block{margin:13px 0}.finding-block h4{margin:0 0 6px;color:var(--blue);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.finding-block pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0f172a;color:#e2e8f0;border-radius:8px;padding:13px;margin:0;max-height:360px;overflow:auto}.artifact-links{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}.artifact-links a{display:inline-block;background:var(--blue);color:white;text-decoration:none;padding:9px 12px;border-radius:7px;font-weight:700}figure{margin:16px 0 0;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:#fff}figure img{display:block;width:100%;height:auto;max-height:720px;object-fit:contain}figcaption{padding:8px 10px;color:var(--muted);font-size:12px}.page-break{break-before:page}@media print{body{background:white}.cover{min-height:100vh;-webkit-print-color-adjust:exact;print-color-adjust:exact}.panel,.finding{box-shadow:none;break-inside:avoid}.artifact-links{display:none}.report{padding:20px}.finding-block pre{max-height:none}.cover h1{font-size:48px}}
</style>"""

    def _slug(self, value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", value) or "target"


class ExternalTools:
    MAX_EXTERNAL_OUTPUT_BYTES = 8 * 1024 * 1024
    MAX_FFUF_RECON_HITS = 10000

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def write_tool_inventory(self) -> None:
        inventory = []
        special_paths = {
            "nuclei_templates": Path.home() / "nuclei-templates",
            "zap_windows": Path(r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"),
        }
        tool_names = [
            "nmap",
            "nuclei",
            "ffuf",
            "whatweb",
            "subfinder",
            "wafw00f",
            "zap",
            "zap.bat",
            "zaproxy",
        ]
        for name in tool_names:
            source = shutil.which(name) or ""
            inventory.append(
                {
                    "tool": name,
                    "available": bool(source),
                    "source": source,
                    "integrated": True,
                    "notes": "",
                }
            )
        for name, path in special_paths.items():
            inventory.append(
                {
                    "tool": name,
                    "available": path.exists(),
                    "source": str(path),
                    "integrated": True,
                    "notes": self._tool_inventory_note(name),
                }
            )
        try:
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            out = REPORTS_DIR / "tool_inventory.json"
            out.write_text(json.dumps(inventory, indent=2, ensure_ascii=False), encoding="utf-8")
            page = [
                "<!doctype html><meta charset='utf-8'><title>Scan Titan - Inventario de Herramientas</title>",
                "<style>body{font-family:Segoe UI,Arial;background:#0f172a;color:#e5e7eb;padding:24px}"
                "table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #334155;padding:8px}"
                "th{background:#111827}.yes{color:#22c55e}.no{color:#f87171}code{color:#93c5fd}</style>",
                "<h1>Scan Titan - Inventario de Herramientas</h1>",
                "<table><thead><tr><th>Herramienta</th><th>Disponible</th><th>Integrada</th><th>Fuente</th><th>Notas</th></tr></thead><tbody>",
            ]
            for item in inventory:
                available = "si" if item["available"] else "no"
                integrated = "si" if item["integrated"] else "no"
                page.append(
                    "<tr>"
                    f"<td>{item['tool']}</td>"
                    f"<td class='{available}'>{available}</td>"
                    f"<td class='{integrated}'>{integrated}</td>"
                    f"<td><code>{item['source']}</code></td>"
                    f"<td>{item['notes']}</td>"
                    "</tr>"
                )
            page.append("</tbody></table>")
            (REPORTS_DIR / "Tool_Inventory.html").write_text("\n".join(page), encoding="utf-8")
        except Exception as exc:
            Console.warn(f"No se pudo escribir el inventario de herramientas: {exc}")

    def _tool_inventory_note(self, name: str) -> str:
        if name == "nuclei_templates":
            return "Directorio local de plantillas Nuclei."
        if name == "zap_windows":
            return "Ruta de instalacion Windows de OWASP ZAP usada cuando zap.bat no esta en PATH."
        return ""

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if self.config.skip_external:
            Console.warn("Herramientas externas omitidas por configuracion")
            return []
        findings: list[Finding] = []
        if self.config.policy.enable_whatweb:
            try:
                await self.config.runtime_control.wait_if_paused()
                if self.config.runtime_control.finish_requested:
                    Console.warn("WhatWeb omitido por finalizacion ordenada")
                    return findings
                findings.extend(await self.run_whatweb(ctx))
            except Exception as exc:
                Console.warn(f"Orquestacion WhatWeb fallida: {exc}")
        else:
            Console.warn("WhatWeb deshabilitado por politica")
        await asyncio.sleep(1.0)
        if self.config.policy.enable_wafw00f:
            try:
                await self.config.runtime_control.wait_if_paused()
                if self.config.runtime_control.finish_requested:
                    Console.warn("wafw00f omitido por finalizacion ordenada")
                    return findings
                findings.extend(await self.run_wafw00f(ctx))
            except Exception as exc:
                Console.warn(f"Orquestacion wafw00f fallida: {exc}")
        else:
            Console.warn("wafw00f deshabilitado por politica")
        await asyncio.sleep(1.0)
        if self.config.policy.enable_subfinder:
            try:
                await self.config.runtime_control.wait_if_paused()
                if self.config.runtime_control.finish_requested:
                    Console.warn("Subfinder omitido por finalizacion ordenada")
                    return findings
                findings.extend(await self.run_subfinder(ctx))
            except Exception as exc:
                Console.warn(f"Orquestacion Subfinder fallida: {exc}")
        else:
            Console.warn("Subfinder deshabilitado por politica")
        await asyncio.sleep(1.0)
        if self.config.policy.enable_nmap:
            try:
                await self.config.runtime_control.wait_if_paused()
                if self.config.runtime_control.finish_requested:
                    Console.warn("Nmap omitido por finalizacion ordenada")
                    return findings
                nmap_findings = await self.run_nmap(ctx)
                findings.extend(nmap_findings)
            except Exception as exc:
                Console.warn(f"Orquestacion Nmap fallida: {exc}")
        else:
            Console.warn("Nmap deshabilitado por politica")
        await asyncio.sleep(2.0)
        # FFUF precedes Nuclei so confirmed route-discovery results can expand
        # Nuclei coverage during the same zero-touch execution.
        if self.config.policy.enable_ffuf:
            try:
                await self.config.runtime_control.wait_if_paused()
                if self.config.runtime_control.finish_requested:
                    Console.warn("FFUF omitido por finalizacion ordenada")
                    return findings
                ffuf_findings = await self.run_ffuf(ctx)
                findings.extend(ffuf_findings)
            except Exception as exc:
                Console.warn(f"Orquestacion FFUF fallida: {exc}")
        else:
            Console.warn("FFUF deshabilitado por politica")
        await asyncio.sleep(1.0)
        if self.config.policy.enable_nuclei:
            try:
                await self.config.runtime_control.wait_if_paused()
                if self.config.runtime_control.finish_requested:
                    Console.warn("Nuclei omitido por finalizacion ordenada")
                    return findings
                nuclei_findings = await self.run_nuclei(ctx)
                findings.extend(nuclei_findings)
            except Exception as exc:
                Console.warn(f"Orquestacion Nuclei fallida: {exc}")
        else:
            Console.warn("Nuclei deshabilitado por politica")
        await asyncio.sleep(1.0)
        if self.config.policy.enable_zap:
            try:
                await self.config.runtime_control.wait_if_paused()
                if self.config.runtime_control.finish_requested:
                    Console.warn("ZAP omitido por finalizacion ordenada")
                    return findings
                zap_findings = await self.run_zap(ctx)
                findings.extend(zap_findings)
            except Exception as exc:
                Console.warn(f"Orquestacion ZAP fallida: {exc}")
        else:
            Console.warn("ZAP deshabilitado por politica")
        return findings

    def _resolve_binary(self, tool: str, default: str) -> str | None:
        tools_cfg = self.config.config_data.get("tools", {}) if isinstance(self.config.config_data.get("tools"), dict) else {}
        tool_cfg = tools_cfg.get(tool, {}) if isinstance(tools_cfg.get(tool), dict) else {}
        configured = str(tool_cfg.get("binary") or default)
        if tool == "whatweb":
            for candidate in (
                BASE_DIR / "tools" / "bin" / "whatweb.cmd",
                BASE_DIR / "tools" / "bin" / "whatweb",
                BASE_DIR / "tools" / "whatweb" / "whatweb",
            ):
                if candidate.exists():
                    return str(candidate)
        resolved = shutil.which(configured)
        if resolved:
            return resolved
        path = Path(configured)
        if not path.is_absolute():
            path = BASE_DIR / path
        if path.exists():
            return str(path)
        return shutil.which(default)

    async def run_whatweb(self, ctx: ScanContext) -> list[Finding]:
        binary = self._resolve_binary("whatweb", "whatweb")
        if not binary:
            Console.warn("WhatWeb no encontrado en PATH")
            return []
        slug = self._slug(ctx.target.display)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_path = REPORTS_DIR / f"whatweb_out_{slug}_{stamp}.json"
        official_mode = await self._whatweb_supports_official_flags(binary)
        cmd = self._whatweb_command(binary, ctx, export_path, official_mode=official_mode)
        Console.step(f"WhatWeb iniciado -> {ctx.target.url}")
        Console.step(f"WhatWeb comando: {self._format_command(cmd)}")
        if self.config.telemetry:
            self.config.telemetry.external_start("whatweb", "technology_fingerprint", ctx.target.display, cmd)
        stdout, stderr, timed_out, returncode, duration = await self._run_command(cmd, self.config.whatweb_timeout)
        findings = self._parse_whatweb(ctx, stdout, export_path if official_mode else None)
        if not findings:
            findings = await self._whatweb_fallback(ctx, stderr)
        self._log_external(
            "whatweb",
            "technology_fingerprint",
            cmd,
            returncode,
            timed_out,
            stderr,
            stdout,
            export_path if official_mode else None,
            duration=duration,
            parsed_count=len(findings),
            empty_reason=self._empty_reason(
                returncode,
                timed_out,
                stderr,
                stdout,
                export_path if official_mode else None,
                len(findings),
            ),
            target=ctx.target.display,
        )
        Console.ok(f"WhatWeb finalizado: rc={returncode} duracion={duration:.1f}s parseados={len(findings)}")
        return findings

    async def run_wafw00f(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.target.url.startswith(("http://", "https://")):
            return []
        binary = self._resolve_binary("wafw00f", "wafw00f")
        if not binary:
            Console.warn("wafw00f no encontrado en PATH")
            return []
        slug = self._slug(ctx.target.display)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_path = REPORTS_DIR / f"wafw00f_out_{slug}_{stamp}.json"
        cmd = [binary, "-a", "-f", "json", ctx.target.url]
        Console.step(f"wafw00f iniciado -> {ctx.target.url}")
        Console.step(f"wafw00f comando: {self._format_command(cmd)}")
        if self.config.telemetry:
            self.config.telemetry.external_start("wafw00f", "waf_fingerprint", ctx.target.display, cmd)
        stdout, stderr, timed_out, returncode, duration = await self._run_command(cmd, self.config.wafw00f_timeout)
        if stdout.strip():
            try:
                export_path.write_text(stdout, encoding="utf-8")
            except OSError:
                pass
        parsed = self._parse_wafw00f(ctx, stdout, stderr)
        findings = []
        if parsed.get("detected"):
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="External/WAFW00F",
                    severity="Info",
                    title="WAF o proteccion perimetral identificada por wafw00f",
                    url=ctx.target.url,
                    evidence=parsed.get("evidence", ""),
                    source="wafw00f",
                    confidence=parsed.get("confidence", "medium"),
                )
            )
        self._log_external(
            "wafw00f",
            "waf_fingerprint",
            cmd,
            returncode,
            timed_out,
            stderr,
            stdout,
            export_path if export_path.exists() else None,
            duration=duration,
            parsed_count=len(findings),
            empty_reason=self._empty_reason(returncode, timed_out, stderr, stdout, export_path if export_path.exists() else None, len(findings)),
            target=ctx.target.display,
        )
        Console.ok(f"wafw00f finalizado: rc={returncode} duracion={duration:.1f}s waf={parsed.get('label') or 'no identificado'}")
        return findings

    def _parse_wafw00f(self, ctx: ScanContext, stdout: str, stderr: str) -> dict[str, Any]:
        text = clean_text(stdout or stderr, 5000)
        lowered = text.lower()
        records: list[dict[str, Any]] = []
        try:
            parsed = json.loads(stdout) if stdout.strip() else None
            if isinstance(parsed, list):
                records = [item for item in parsed if isinstance(item, dict)]
            elif isinstance(parsed, dict):
                for key in ("results", "data", "items"):
                    if isinstance(parsed.get(key), list):
                        records = [item for item in parsed[key] if isinstance(item, dict)]
                        break
                if not records:
                    records = [parsed]
        except json.JSONDecodeError:
            records = []

        labels: list[str] = []
        vendors: list[str] = []
        evidences: list[str] = []
        detected = False
        for record in records:
            record_detected = record.get("detected")
            firewall = clean_text(
                record.get("firewall")
                or record.get("waf")
                or record.get("name")
                or record.get("product")
                or record.get("technology"),
                160,
            )
            manufacturer = clean_text(
                record.get("manufacturer")
                or record.get("vendor")
                or record.get("company"),
                120,
            )
            if firewall and firewall.lower() not in {"none", "no waf", "unknown"}:
                detected = detected or record_detected is not False
                label = f"{firewall} ({manufacturer})" if manufacturer else firewall
                labels.append(label)
                if manufacturer:
                    vendors.append(manufacturer)
            elif record_detected is True:
                detected = True
            for key in ("reason", "reasoning", "evidence", "confidence"):
                value = clean_text(record.get(key), 220)
                if value:
                    evidences.append(value)

        if not labels:
            regexes = [
                r"behind\s+(.+?)\s+(?:waf|firewall)",
                r"is\s+behind\s+(.+)",
                r"identified\s+as\s+(.+)",
            ]
            for pattern in regexes:
                match = re.search(pattern, text, re.I)
                if match:
                    candidate = clean_text(match.group(1), 140).strip(" .:-")
                    if candidate and "no waf" not in candidate.lower():
                        labels.append(candidate)
                        detected = True
                        break

        no_waf = "no waf" in lowered or "seems to be behind no waf" in lowered
        label = " | ".join(dict.fromkeys(labels))
        vendor = " | ".join(dict.fromkeys(vendors))
        if detected and label:
            status = "Detectado"
            evidence = clean_text(
                " | ".join(
                    dict.fromkeys(
                        [
                            f"wafw00f detecto {label}",
                            f"Fabricante: {vendor}" if vendor else "",
                            *evidences,
                            text,
                        ]
                    )
                ),
                1800,
            )
            confidence = "high"
        elif no_waf:
            status = "No identificado"
            evidence = "wafw00f no identifico WAF o proteccion perimetral especifica."
            confidence = "medium"
        else:
            status = "Sin resultado util"
            evidence = clean_text(text or "wafw00f no devolvio evidencia util.", 1200)
            confidence = "low"

        ctx.recon["wafw00f_status"] = status
        ctx.recon["wafw00f_vendor"] = vendor or label
        ctx.recon["wafw00f_evidence"] = evidence
        if detected and label:
            ctx.recon["waf_cdn"] = sorted(set(ctx.recon.get("waf_cdn", []) + [label]))
        return {
            "detected": bool(detected and label),
            "label": label,
            "vendor": vendor,
            "status": status,
            "evidence": evidence,
            "confidence": confidence,
        }

    async def run_subfinder(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target.is_ip:
            return []
        binary = self._resolve_binary("subfinder", "subfinder")
        if not binary:
            Console.warn("Subfinder no encontrado en PATH")
            return []
        scan_domain = self._registrable_domain(ctx.target.host)
        max_minutes = max(1, int((self.config.subfinder_timeout + 59) / 60))
        cmd = [binary, "-d", scan_domain, "-silent", "-nc", "-max-time", str(max_minutes)]
        Console.step(f"Subfinder iniciado -> {scan_domain} (objetivo original: {ctx.target.host})")
        Console.step(f"Subfinder comando: {self._format_command(cmd)}")
        if self.config.telemetry:
            self.config.telemetry.external_start("subfinder", "passive_subdomains", ctx.target.display, cmd)
        stdout, stderr, timed_out, returncode, duration = await self._run_command(cmd, self.config.subfinder_timeout)
        findings = self._parse_subfinder(ctx, stdout)
        self._log_external(
            "subfinder",
            "passive_subdomains",
            cmd,
            returncode,
            timed_out,
            stderr,
            stdout,
            duration=duration,
            parsed_count=len(findings),
            empty_reason=self._empty_reason(returncode, timed_out, stderr, stdout, None, len(findings)),
            target=scan_domain,
        )
        Console.ok(f"Subfinder finalizado: rc={returncode} duracion={duration:.1f}s parseados={len(findings)}")
        return findings

    async def run_ffuf(self, ctx: ScanContext) -> list[Finding]:
        binary = self._resolve_binary("ffuf", "ffuf")
        if not binary:
            Console.warn("ffuf no encontrado en PATH")
            return []
        wordlist = self._write_ffuf_wordlist(ctx)
        slug = self._slug(ctx.target.display)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_path = REPORTS_DIR / f"ffuf_out_{slug}_{stamp}.json"
        # Route discovery must start at the web origin.  Appending FUZZ to a
        # supplied login/deep-link path hides sibling routes and produced very
        # incomplete recon on targets such as /app/login.
        target_url = urllib.parse.urljoin(self._origin_url(ctx.target.url), "FUZZ")
        soft404_signature = await self._ffuf_soft404_signature(ctx)
        filter_args = self._ffuf_filter_args(soft404_signature)
        cmd = [
            binary,
            "-k",
            "-w",
            str(wordlist),
            "-u",
            target_url,
            "-mc",
            "200,204,301,302,307,308,401,403,405,500",
            *filter_args,
            "-rate",
            str(max(1, self.config.ffuf_rate)),
            "-t",
            str(max(1, min(self.config.ffuf_threads, 50))),
            "-timeout",
            str(max(3, int(self.config.timeout))),
            "-of",
            "json",
            "-o",
            str(export_path),
            "-s",
        ]
        Console.step(f"FFUF iniciado para fuzzing de rutas -> {ctx.target.url}")
        Console.step(f"FFUF comando: {self._format_command(cmd)}")
        if self.config.telemetry:
            self.config.telemetry.external_start("ffuf", "route_fuzzing", ctx.target.display, cmd)
        stdout, stderr, timed_out, returncode, duration = await self._run_command(cmd, self.config.ffuf_timeout)
        findings, hit_count = self._parse_ffuf(ctx, export_path, stdout, soft404_signature)
        self._log_external(
            "ffuf",
            "route_fuzzing",
            cmd,
            returncode,
            timed_out,
            stderr,
            stdout,
            export_path,
            duration=duration,
            parsed_count=hit_count,
            empty_reason=self._empty_reason(returncode, timed_out, stderr, stdout, export_path, hit_count),
            target=ctx.target.display,
        )
        try:
            wordlist.unlink(missing_ok=True)
        except Exception:
            pass
        Console.ok(f"FFUF finalizado: rc={returncode} duracion={duration:.1f}s rutas={hit_count} hallazgos={len(findings)}")
        return findings

    async def run_nmap(self, ctx: ScanContext) -> list[Finding]:
        binary = self._resolve_binary("nmap", "nmap")
        if not binary:
            Console.warn("Nmap no encontrado en PATH")
            return []
        nmap_target = ctx.target.host or ctx.target.ip
        slug = self._slug(ctx.target.display)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        def xml_path(profile: str) -> Path:
            return REPORTS_DIR / f"nmap_out_{slug}_{profile}_{stamp}.xml"

        network_ports = self._nmap_ports_for(
            ctx,
            "1-1024,2049,3000,5000,5601,5985,5986,8000,8080,8081,8443,8888,9000,9090,9091,9443,10000,10443",
        )
        tls_ports = self._nmap_ports_for(ctx, "443,8443,9443,10443")
        http_ports = self._nmap_ports_for(ctx, "80,443,8080,8443,9000,9090,9091")
        cve_ports = self._nmap_ports_for(ctx, "80,443,445,8080,8443,9000,9090,9091")
        findings: list[Finding] = []
        profiles = [
            (
                "network_vulnerability_scan",
                [
                    binary,
                    "-sV",
                    "-Pn",
                    "--version-light",
                    "-p",
                    network_ports,
                    "--script",
                    "default or (vuln and safe) or sslv2 or ssl-enum-ciphers",
                    "-oX",
                    str(xml_path("network_vulnerability_scan")),
                    nmap_target,
                ],
                xml_path("network_vulnerability_scan"),
            ),
            (
                "ssl_tls_surface",
                [
                    binary,
                    "-sV",
                    "-Pn",
                    "-p",
                    tls_ports,
                    "--script",
                    "ssl-cert,ssl-enum-ciphers,sslv2",
                    "-oX",
                    str(xml_path("ssl_tls_surface")),
                    nmap_target,
                ],
                xml_path("ssl_tls_surface"),
            ),
            (
                "http_slowloris_check",
                [
                    binary,
                    "-sV",
                    "-Pn",
                    "-p",
                    http_ports,
                    "--script",
                    "http-slowloris-check",
                    "-oX",
                    str(xml_path("http_slowloris_check")),
                    nmap_target,
                ],
                xml_path("http_slowloris_check"),
            ),
            (
                "vulners_cvss",
                [
                    binary,
                    "-sV",
                    "--version-all",
                    "-Pn",
                    "-p",
                    cve_ports,
                    "--script",
                    "vulners",
                    "--script-args",
                    "mincvss=5.0",
                    "-oX",
                    str(xml_path("vulners_cvss")),
                    nmap_target,
                ],
                xml_path("vulners_cvss"),
            ),
        ]
        profiles = [item for item in profiles if self.config.external_profile_enabled("nmap", item[0])]
        if not profiles:
            Console.warn("Nmap omitido: no hay perfiles habilitados en config.yaml")
            return []
        for name, cmd, export_path in profiles:
            await self.config.runtime_control.wait_if_paused()
            if self.config.runtime_control.finish_requested:
                Console.warn(f"Perfil Nmap omitido por finalizacion ordenada: {name}")
                break
            Console.step(f"Nmap perfil iniciado: {name} -> {nmap_target}")
            Console.step(f"Nmap comando [{name}]: {self._format_command(cmd)}")
            if self.config.telemetry:
                self.config.telemetry.external_start("nmap", name, nmap_target, cmd)
            profile_timeout = self.config.external_profile_timeout("nmap", name, self.config.nmap_timeout)
            stdout, stderr, timed_out, returncode, duration = await self._run_command(cmd, profile_timeout)
            if timed_out:
                Console.warn(f"Timeout en perfil Nmap: {name}")
            elif returncode not in {0, None}:
                Console.warn(f"Perfil Nmap finalizo con codigo {returncode}: {clean_text(stderr, 220)}")
            xml_text = stdout
            try:
                if export_path.exists() and export_path.stat().st_size > 0:
                    xml_text = export_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                Console.warn(f"No se pudo leer la evidencia XML de Nmap: {clean_text(exc, 220)}")
            parsed = self._parse_nmap(ctx, xml_text, name)
            Console.ok(f"Nmap perfil finalizado: {name} rc={returncode} duracion={duration:.1f}s parseados={len(parsed)}")
            findings.extend(parsed)
            self._log_external(
                "nmap",
                name,
                cmd,
                returncode,
                timed_out,
                stderr,
                stdout,
                export_path,
                duration=duration,
                parsed_count=len(parsed),
                empty_reason=self._empty_reason(
                    returncode,
                    timed_out,
                    stderr,
                    stdout,
                    export_path,
                    len(parsed),
                ),
                target=nmap_target,
            )
            await asyncio.sleep(2.0)
        return findings

    def _nmap_ports_for(self, ctx: ScanContext, base_ports: str) -> str:
        intervals: list[tuple[int, int]] = []

        def add(raw: Any) -> None:
            text = str(raw or "").strip()
            if not text:
                return
            for token in re.split(r"[,;\s]+", text):
                candidate = token.strip()
                if not candidate:
                    continue
                match = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", candidate)
                if match:
                    start = int(match.group(1))
                    end = int(match.group(2) or start)
                    if 1 <= start <= end <= 65535:
                        intervals.append((start, end))
                    continue
                service_match = re.search(r"\b(\d{1,5})/(?:tcp|udp)\b", candidate, flags=re.IGNORECASE)
                if service_match:
                    port = int(service_match.group(1))
                    if 1 <= port <= 65535:
                        intervals.append((port, port))

        add(base_ports)
        if ctx.target.port:
            add(str(ctx.target.port))
        for bucket in ("open_ports", "ports_services", "services"):
            for item in ctx.recon.get(bucket, []) or []:
                add(item)
        if not intervals:
            return base_ports
        merged: list[list[int]] = []
        for start, end in sorted(set(intervals)):
            if merged and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        return ",".join(str(start) if start == end else f"{start}-{end}" for start, end in merged)

    async def run_nuclei(self, ctx: ScanContext) -> list[Finding]:
        binary = self._resolve_binary("nuclei", "nuclei")
        if not binary:
            Console.warn("Nuclei no encontrado en PATH")
            return []
        profiles = [
            item
            for item in self._nuclei_profiles(binary, ctx)
            if self.config.external_profile_enabled("nuclei", item[0])
        ]
        all_findings: list[Finding] = []
        seen: set[str] = set()
        if not profiles:
            Console.warn("Nuclei omitido: no hay perfiles habilitados en config.yaml")
            return []
        for name, cmd, export_path in profiles:
            await self.config.runtime_control.wait_if_paused()
            if self.config.runtime_control.finish_requested:
                Console.warn(f"Perfil Nuclei omitido por finalizacion ordenada: {name}")
                break
            if export_path.exists():
                export_path.unlink()
            Console.step(f"Nuclei perfil iniciado: {name}")
            Console.step(f"Nuclei comando [{name}]: {self._format_command(cmd)}")
            if self.config.telemetry:
                self.config.telemetry.external_start("nuclei", name, ctx.target.display, cmd)
            profile_timeout = self.config.external_profile_timeout("nuclei", name, self.config.nuclei_timeout)
            stdout, stderr, timed_out, returncode, duration = await self._run_command(cmd, profile_timeout)
            if timed_out:
                Console.warn(f"Timeout en perfil Nuclei: {name}")
            elif returncode not in {0, None}:
                Console.warn(f"Perfil Nuclei finalizo con codigo {returncode}: {clean_text(stderr, 220)}")
            findings, parser_error = self._parse_nuclei_with_status(ctx, export_path, stdout)
            empty_reason = self._nuclei_empty_reason(
                returncode,
                timed_out,
                stderr,
                stdout,
                export_path,
                len(findings),
                parser_error,
            )
            self._log_external(
                "nuclei",
                name,
                cmd,
                returncode,
                timed_out,
                stderr,
                stdout,
                export_path,
                duration=duration,
                parsed_count=len(findings),
                empty_reason=empty_reason,
                target=ctx.target.display,
            )
            if findings:
                Console.ok(f"Nuclei perfil util: {name} ({len(findings)} hallazgo(s))")
                for finding in findings:
                    if finding.fingerprint not in seen:
                        seen.add(finding.fingerprint)
                        all_findings.append(finding)
            else:
                Console.warn(f"Nuclei {name}: {empty_reason}")
            Console.ok(f"Nuclei perfil finalizado: {name} rc={returncode} duracion={duration:.1f}s parseados={len(findings)}")
        return all_findings

    async def run_zap(self, ctx: ScanContext) -> list[Finding]:
        mode = self.config.zap_mode
        if mode == "active" and not self.config.policy.allow_state_changing_api_tests:
            Console.warn("Modo activo de ZAP degradado a baseline por politica")
            mode = "baseline"
        slug = self._slug(ctx.target.display)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_path = REPORTS_DIR / f"zap_alerts_{slug}_{stamp}.json"
        command_label = ["ZAP API", self.config.zap_api_url, f"mode={mode}"]
        started = time.monotonic()
        zap_process: asyncio.subprocess.Process | None = None
        started_daemon = False
        Console.step(f"Integracion ZAP iniciada: modo={mode} -> {ctx.target.url}")
        if self.config.telemetry:
            self.config.telemetry.external_start("zap", mode, ctx.target.display, command_label)
        try:
            ready = await self._zap_wait_ready(self.config.zap_startup_timeout if not self.config.zap_start_daemon else 3)
            if not ready:
                if not self.config.zap_start_daemon:
                    reason = "La API de ZAP no responde y start_daemon=false."
                    Console.warn(reason)
                    self._log_external(
                        "zap",
                        mode,
                        command_label,
                        -1,
                        False,
                        reason,
                        "",
                        export_path,
                        duration=time.monotonic() - started,
                        parsed_count=0,
                        empty_reason=reason,
                        target=ctx.target.display,
                    )
                    return []
                binary = self._resolve_zap_binary()
                if not binary:
                    reason = "No se encontro el binario de ZAP en PATH ni en rutas comunes de Windows."
                    Console.warn(reason)
                    self._log_external(
                        "zap",
                        mode,
                        ["zap.bat", "-daemon"],
                        -1,
                        False,
                        reason,
                        "",
                        export_path,
                        duration=time.monotonic() - started,
                        parsed_count=0,
                        empty_reason=reason,
                        target=ctx.target.display,
                    )
                    return []
                daemon_cmd = self._zap_daemon_command(binary)
                Console.step(f"ZAP daemon comando: {self._format_command(daemon_cmd)}")
                daemon_cwd = str(Path(binary).resolve().parent)
                zap_process = await asyncio.create_subprocess_exec(
                    *daemon_cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    cwd=daemon_cwd,
                )
                started_daemon = True
                ready = await self._zap_wait_ready(self.config.zap_startup_timeout)
            if not ready:
                reason = "El daemon de ZAP no quedo listo antes del timeout de inicio."
                Console.warn(reason)
                self._log_external(
                    "zap",
                    mode,
                    command_label,
                    -1,
                    True,
                    reason,
                    "",
                    export_path,
                    duration=time.monotonic() - started,
                    parsed_count=0,
                    empty_reason=reason,
                    target=ctx.target.display,
                )
                return []

            version = await self._zap_api("core/view/version")
            Console.ok(f"API de ZAP lista: version={version.get('version', '-')}")
            seeds = self._zap_seed_urls(ctx)
            accessed = await self._zap_access_urls(ctx, seeds)
            spider_count = 0
            if mode in {"baseline", "active"}:
                spider_count = await self._zap_spider(ctx, ctx.target.url)
            passive_records = await self._zap_wait_passive(ctx)
            active_count = 0
            active_completed = True
            active_progress = 100
            active_stop_reason = ""
            if mode == "active":
                active_count, active_completed, active_progress, active_stop_reason = await self._zap_active_scan(
                    ctx,
                    ctx.target.url,
                )
                passive_records = await self._zap_wait_passive(ctx)
            alerts_payload = await self._zap_api(
                "core/view/alerts",
                {
                    "baseurl": ctx.target.url,
                    "start": "0",
                    "count": str(max(1, self.config.zap_max_alerts)),
                },
            )
            alerts = alerts_payload.get("alerts", [])
            if not isinstance(alerts, list):
                alerts = []
            raw_alert_count = len(alerts)
            alerts, filtered_zap_alerts = await self._filter_zap_soft_auth_redirect_alerts(ctx, alerts)
            if filtered_zap_alerts:
                Console.ok(f"Falsos positivos ZAP por redireccion a login filtrados: {len(filtered_zap_alerts)}")
            urls_payload = await self._zap_api("core/view/urls")
            self._zap_merge_recon(ctx, alerts, urls_payload)
            export_payload = {
                "schema": "scan_titan_zap_alerts_v1",
                "target": ctx.target.url,
                "mode": mode,
                "version": version.get("version", ""),
                "accessed_urls": accessed,
                "spider_records": spider_count,
                "active_records": active_count,
                "active_completed": active_completed,
                "active_progress": active_progress,
                "active_stop_reason": active_stop_reason,
                "passive_records_remaining": passive_records,
                "raw_alert_count": raw_alert_count,
                "filtered_soft_auth_alerts": filtered_zap_alerts,
                "alerts": alerts,
            }
            export_path.write_text(json.dumps(export_payload, indent=2, ensure_ascii=False), encoding="utf-8")
            findings = self._parse_zap_alerts(ctx, alerts)
            partial_reason = (
                f"El escaneo activo de ZAP se detuvo en {active_progress}% ({active_stop_reason})."
                if not active_completed
                else ""
            )
            empty_reason = partial_reason or ("" if findings else (
                "ZAP finalizo sin alertas reportables."
                + (
                    f" Se filtraron {len(filtered_zap_alerts)} falso(s) positivo(s) por redireccion a login."
                    if filtered_zap_alerts
                    else ""
                )
            ))
            self._log_external(
                "zap",
                mode,
                command_label,
                0,
                active_stop_reason == "timeout",
                partial_reason,
                json.dumps(
                    {
                        "version": version.get("version", ""),
                        "alerts": len(alerts),
                        "raw_alerts": raw_alert_count,
                        "filtered_soft_auth": len(filtered_zap_alerts),
                        "accessed": accessed,
                        "spider": spider_count,
                        "active": active_count,
                    },
                    ensure_ascii=False,
                ),
                export_path,
                duration=time.monotonic() - started,
                parsed_count=len(findings),
                empty_reason=empty_reason,
                target=ctx.target.display,
            )
            Console.ok(
                "ZAP finalizado: "
                f"modo={mode} urls_accedidas={accessed} spider={spider_count} "
                f"activo={active_count} alertas={len(alerts)}/{raw_alert_count} hallazgos={len(findings)}"
            )
            return findings
        except Exception as exc:
            reason = clean_text(exc, 500)
            Console.warn(f"Integracion ZAP fallida: {reason}")
            self._log_external(
                "zap",
                mode,
                command_label,
                -1,
                False,
                reason,
                "",
                export_path,
                duration=time.monotonic() - started,
                parsed_count=0,
                empty_reason=reason,
                target=ctx.target.display,
            )
            return []
        finally:
            if started_daemon and self.config.zap_shutdown_after_scan:
                await self._zap_shutdown(zap_process)

    def _resolve_zap_binary(self) -> str | None:
        resolved = self._resolve_binary("zap", "zap.bat")
        if resolved:
            return resolved
        for name in ("zap.bat", "zap", "zaproxy"):
            resolved = shutil.which(name)
            if resolved:
                return resolved
        common_paths = [
            Path(r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"),
            Path(r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat"),
            Path(r"C:\Program Files (x86)\ZAP\Zed Attack Proxy\zap.bat"),
            Path(r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat"),
        ]
        for path in common_paths:
            if path.exists():
                return str(path)
        return None

    def _zap_daemon_command(self, binary: str) -> list[str]:
        cmd = [
            binary,
            "-daemon",
            "-host",
            self.config.zap_host,
            "-port",
            str(self.config.zap_port),
            "-config",
            "api.addrs.addr.name=.*",
            "-config",
            "api.addrs.addr.regex=true",
        ]
        if self.config.zap_api_key:
            cmd.extend(["-config", f"api.key={self.config.zap_api_key}"])
        else:
            cmd.extend(["-config", "api.disablekey=true"])
        return cmd

    async def _zap_wait_ready(self, timeout_seconds: int) -> bool:
        deadline = time.monotonic() + max(1, timeout_seconds)
        while time.monotonic() < deadline:
            try:
                await self._zap_api("core/view/version", timeout=5)
                return True
            except Exception:
                await asyncio.sleep(2.0)
        return False

    async def _zap_api(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        clean_path = path.strip("/")
        url = f"{self.config.zap_api_url}/JSON/{clean_path}/"
        query = {str(k): str(v) for k, v in (params or {}).items() if v is not None}
        if self.config.zap_api_key:
            query["apikey"] = self.config.zap_api_key
        request_timeout = aiohttp.ClientTimeout(total=max(3, int(timeout or min(self.config.zap_timeout, 30))))
        async with aiohttp.ClientSession(timeout=request_timeout, trust_env=False) as session:
            async with session.get(url, params=query) as response:
                text = await response.text(errors="replace")
        try:
            data = json.loads(text or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"ZAP devolvio una respuesta no JSON desde {clean_path}: {clean_text(text, 200)}") from exc
        if isinstance(data, dict) and data.get("code"):
            code = str(data.get("code"))
            message = data.get("message") or data.get("detail") or ""
            if code.lower() in {"bad_api_key", "unauthorized"}:
                raise RuntimeError(
                    "ZAP rechazo la API key configurada. Defina tools.zap.api_key o permita que Scan Titan inicie ZAP."
                )
            raise RuntimeError(f"Error API ZAP {code}: {message}")
        return data if isinstance(data, dict) else {}

    def _zap_seed_urls(self, ctx: ScanContext) -> list[str]:
        seeds: list[str] = [ctx.target.url]
        for key in ("discovered_paths", "unauthenticated_routes", "site_map"):
            for item in ctx.recon.get(key, []) or []:
                seeds.append(self._zap_url_from_recon_item(ctx, item))
        for item in ctx.recon.get("endpoints", []) or []:
            if isinstance(item, dict):
                seeds.append(str(item.get("url") or ""))
            else:
                seeds.append(str(item or ""))
        clean: list[str] = []
        seen: set[str] = set()
        for raw in seeds:
            url = self._zap_normalize_seed(ctx, raw)
            if not url:
                continue
            key = url.lower()
            if key not in seen:
                seen.add(key)
                clean.append(url)
            if len(clean) >= max(1, self.config.zap_max_seed_urls):
                break
        return clean

    def _zap_url_from_recon_item(self, ctx: ScanContext, item: Any) -> str:
        if isinstance(item, dict):
            return str(item.get("url") or item.get("path") or "")
        text = str(item or "").strip()
        if not text:
            return ""
        if self._zap_reject_non_url_artifact(text):
            return ""
        match = re.search(r"https?://[^\s,|)]+", text)
        if match:
            return match.group(0)
        first = text.split()[0].strip()
        if first.startswith("/"):
            return urllib.parse.urljoin(ctx.target.url, first)
        return first

    def _zap_normalize_seed(self, ctx: ScanContext, raw: str) -> str:
        value = str(raw or "").strip()
        value = value.strip("'\"`[](){}<>,;")
        if not value:
            return ""
        if self._zap_reject_non_url_artifact(value):
            return ""
        if value.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(value)
            if not self._zap_valid_same_target_url(ctx, parsed):
                return ""
            clean_path = parsed.path or "/"
            if self._zap_reject_non_url_artifact(clean_path):
                return ""
            return parsed._replace(path=clean_path, params="", fragment="").geturl()
        if re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
            return ""
        if value.startswith("/"):
            if self._zap_reject_non_url_artifact(value):
                return ""
            return urllib.parse.urljoin(ctx.target.url, value)
        return ""

    @staticmethod
    def _zap_reject_non_url_artifact(value: str) -> bool:
        text = str(value or "").strip()
        if not text:
            return True
        if any(token in text for token in ('"*://', "'*://", "*://", "*.", "*", '"', "`")):
            return True
        if any(ch in text for ch in ("\r", "\n", "\t")):
            return True
        lowered = text.lower()
        artifact_markers = (
            "script-src",
            "connect-src",
            "img-src",
            "frame-src",
            "default-src",
            "style-src",
            "child-src",
            "font-src",
            "media-src",
            "worker-src",
            "manifest-src",
            "wss://*",
            "ws://*",
            "data:",
            "blob:",
            "filesystem:",
            "nonce-",
            "sha256-",
            "sha384-",
            "sha512-",
            "coin-hive",
            "coinhive",
            "jsecoin",
        )
        if any(marker in lowered for marker in artifact_markers):
            return True
        if re.search(r"\s+(src|href|connect|img|frame|font|style)-", lowered):
            return True
        if re.search(r"[\x00-\x1f]", text):
            return True
        return False

    @staticmethod
    def _zap_valid_same_target_url(ctx: ScanContext, parsed: urllib.parse.ParseResult) -> bool:
        if parsed.scheme not in {"http", "https"}:
            return False
        if not parsed.hostname:
            return False
        expected = urllib.parse.urlparse(ctx.target.url)
        if not expected.hostname:
            return False
        if parsed.hostname.lower() != expected.hostname.lower():
            return False
        if parsed.port and expected.port and parsed.port != expected.port:
            return False
        if parsed.username or parsed.password:
            return False
        return True

    async def _zap_access_urls(self, ctx: ScanContext, urls: list[str]) -> int:
        accessed = 0
        invalid_rejections = 0
        api_errors = 0
        for index, url in enumerate(urls, start=1):
            await self.config.runtime_control.wait_if_paused()
            if self.config.runtime_control.finish_requested:
                break
            Console.heartbeat("zap_access", clean_text(url, 80), index, accessed)
            try:
                await self._zap_api("core/action/accessUrl", {"url": url, "followRedirects": "true"}, timeout=20)
                accessed += 1
            except Exception as exc:
                message = clean_text(exc, 180)
                lowered = message.lower()
                if "illegal_parameter" in lowered or "parametro facilitado" in lowered or "parámetro facilitado" in lowered:
                    invalid_rejections += 1
                    if invalid_rejections <= 3:
                        Console.warn(f"ZAP omitio URL semilla invalida: {clean_text(url, 80)}")
                else:
                    api_errors += 1
                    if api_errors <= 5:
                        Console.warn(f"ZAP no pudo acceder la URL semilla: {clean_text(url, 80)} :: {message}")
            await asyncio.sleep(0.15)
        if invalid_rejections > 3:
            Console.warn(f"ZAP omitio {invalid_rejections} URL(s) semilla invalidas antes de escanear.")
        if api_errors > 5:
            Console.warn(f"ZAP registro {api_errors} error(es) de acceso a semillas; revise External_Tools_Observability.html.")
        return accessed

    def _external_deadline(self, timeout_seconds: int) -> float | None:
        seconds = max(0, int(timeout_seconds or 0))
        return None if seconds == 0 else time.monotonic() + seconds

    @staticmethod
    def _deadline_open(deadline: float | None) -> bool:
        return deadline is None or time.monotonic() < deadline

    @staticmethod
    def _timeout_text(timeout_seconds: int) -> str:
        seconds = max(0, int(timeout_seconds or 0))
        return "sin limite" if seconds == 0 else f"{seconds}s"

    async def _zap_spider(self, ctx: ScanContext, url: str) -> int:
        Console.step(f"Spider ZAP iniciado -> {url}")
        scan = await self._zap_api(
            "spider/action/scan",
            {
                "url": url,
                "maxChildren": str(max(1, self.config.zap_max_children)),
                "recurse": "true",
            },
            timeout=20,
        )
        scan_id = str(scan.get("scan") or scan.get("scanId") or "0")
        deadline = self._external_deadline(self.config.zap_spider_timeout)
        last_status = "0"
        while self._deadline_open(deadline):
            await self.config.runtime_control.wait_if_paused()
            if self.config.runtime_control.finish_requested:
                break
            status = await self._zap_api("spider/view/status", {"scanId": scan_id}, timeout=10)
            last_status = str(status.get("status", "0"))
            Console.heartbeat(
                "zap_spider",
                f"scan={scan_id} avance={last_status}% limite={self._timeout_text(self.config.zap_spider_timeout)}",
                int(last_status or 0),
                0,
            )
            if int(last_status or 0) >= 100:
                break
            await asyncio.sleep(3.0)
        results = await self._zap_api("spider/view/results", {"scanId": scan_id}, timeout=20)
        found = results.get("results", [])
        if isinstance(found, list):
            ctx.recon["site_map"] = sorted(set(ctx.recon.get("site_map", []) + [str(item) for item in found]))[:1200]
            return len(found)
        return 0

    async def _zap_wait_passive(self, ctx: ScanContext) -> int:
        Console.step("Espera de analisis pasivo ZAP iniciada")
        deadline = self._external_deadline(self.config.zap_passive_timeout)
        remaining = 0
        while self._deadline_open(deadline):
            await self.config.runtime_control.wait_if_paused()
            if self.config.runtime_control.finish_requested:
                break
            records = await self._zap_api("pscan/view/recordsToScan", timeout=10)
            remaining = int(records.get("recordsToScan") or 0)
            Console.heartbeat(
                "zap_passive",
                f"pendientes={remaining} limite={self._timeout_text(self.config.zap_passive_timeout)}",
                remaining,
                0,
            )
            if remaining <= 0:
                break
            await asyncio.sleep(2.0)
        return remaining

    async def _zap_active_scan(self, ctx: ScanContext, url: str) -> tuple[int, bool, int, str]:
        Console.step(f"Analisis activo ZAP iniciado -> {url}")
        scan = await self._zap_api(
            "ascan/action/scan",
            {"url": url, "recurse": "true", "inScopeOnly": "false"},
            timeout=20,
        )
        scan_id = str(scan.get("scan") or scan.get("scanId") or "0")
        deadline = self._external_deadline(self.config.zap_active_timeout)
        last_status = "0"
        stop_reason = ""
        while self._deadline_open(deadline):
            await self.config.runtime_control.wait_if_paused()
            if self.config.runtime_control.finish_requested:
                stop_reason = "finalizacion_solicitada"
                break
            status = await self._zap_api("ascan/view/status", {"scanId": scan_id}, timeout=10)
            last_status = str(status.get("status", "0"))
            Console.heartbeat(
                "zap_active",
                f"scan={scan_id} avance={last_status}% limite={self._timeout_text(self.config.zap_active_timeout)}",
                int(last_status or 0),
                0,
            )
            if int(last_status or 0) >= 100:
                break
            await asyncio.sleep(5.0)
        progress = int(last_status or 0)
        completed = progress >= 100
        if not completed:
            stop_reason = stop_reason or ("timeout" if deadline is not None else "finalizacion_solicitada")
            if deadline is not None or self.config.runtime_control.finish_requested:
                with contextlib.suppress(Exception):
                    await self._zap_api("ascan/action/stop", {"scanId": scan_id}, timeout=20)
        messages = await self._zap_api("ascan/view/messagesIds", {"scanId": scan_id}, timeout=20)
        ids = messages.get("messagesIds", [])
        return len(ids) if isinstance(ids, list) else 0, completed, progress, stop_reason

    async def _zap_shutdown(self, process: asyncio.subprocess.Process | None) -> None:
        with contextlib.suppress(Exception):
            await self._zap_api("core/action/shutdown", timeout=5)
        if process is None:
            return
        try:
            await asyncio.wait_for(process.communicate(), timeout=12)
        except asyncio.TimeoutError:
            await self._terminate_process(process)
        except Exception:
            pass

    async def _filter_zap_soft_auth_redirect_alerts(
        self,
        ctx: ScanContext,
        alerts: list[Any],
    ) -> tuple[list[Any], list[dict[str, str]]]:
        if not alerts:
            return [], []
        baseline = None
        kept: list[Any] = []
        filtered: list[dict[str, str]] = []
        for alert in alerts:
            if not self._is_zap_external_redirect_alert(alert):
                kept.append(alert)
                continue
            url = str(alert.get("url") or "")
            if not self._is_same_target_url(ctx, url):
                kept.append(alert)
                continue
            if baseline is None:
                baseline = await self._zap_soft_auth_baseline(ctx)
            reason = await self._zap_soft_auth_filter_reason(ctx, alert, baseline)
            if not reason:
                kept.append(alert)
                continue
            filtered.append(
                {
                    "alert": str(alert.get("alert") or alert.get("name") or "ZAP alert"),
                    "plugin": str(alert.get("pluginId") or alert.get("alertRef") or ""),
                    "url": url,
                    "param": str(alert.get("param") or ""),
                    "attack": clean_text(alert.get("attack") or "", 180),
                    "reason": reason,
                }
            )
        if filtered:
            labels = [f"{item['alert']} @ {item['url']} :: {item['reason']}" for item in filtered[:120]]
            ctx.recon["zap_filtered_alerts"] = sorted(set(ctx.recon.get("zap_filtered_alerts", []) + labels))[:300]
        return kept, filtered

    def _is_zap_external_redirect_alert(self, alert: Any) -> bool:
        if not isinstance(alert, dict):
            return False
        title = str(alert.get("alert") or alert.get("name") or "").lower()
        plugin = str(alert.get("pluginId") or alert.get("alertRef") or "")
        return plugin == "20019" or any(
            token in title
            for token in (
                "external redirect",
                "redirección externa",
                "redireccion externa",
                "open redirect",
                "unvalidated redirect",
            )
        )

    def _is_same_target_url(self, ctx: ScanContext, url: str) -> bool:
        parsed = urllib.parse.urlparse(str(url or ""))
        if not parsed.scheme or not parsed.netloc:
            return False
        expected = urllib.parse.urlparse(ctx.target.url)
        return parsed.hostname and expected.hostname and parsed.hostname.lower() == expected.hostname.lower()

    async def _zap_soft_auth_baseline(self, ctx: ScanContext) -> Any:
        token = f"/scan-titan-zap-softauth-{int(time.time())}-987654321"
        return await ctx.http.request(
            "GET",
            urllib.parse.urljoin(ctx.target.url, token),
            allow_redirects=False,
            timeout=min(ctx.limits.timeout, 6),
        )

    async def _zap_soft_auth_filter_reason(self, ctx: ScanContext, alert: dict[str, Any], baseline: Any) -> str:
        url = str(alert.get("url") or "")
        if not url:
            return ""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        if is_authentication_url(url):
            return ""
        result = await ctx.http.request(
            "GET",
            url,
            allow_redirects=False,
            timeout=min(ctx.limits.timeout, 6),
        )
        if not result or not is_soft_auth_redirect(result, baseline, path):
            return ""
        reason = soft_auth_redirect_reason(result, baseline, path)
        return reason or "validated soft-auth catch-all response"

    def _zap_merge_recon(self, ctx: ScanContext, alerts: list[Any], urls_payload: dict[str, Any]) -> None:
        labels = []
        for item in alerts[:300]:
            if not isinstance(item, dict):
                continue
            risk = item.get("risk") or item.get("riskdesc") or "-"
            labels.append(f"{risk}: {item.get('alert') or item.get('name') or '-'} @ {item.get('url') or '-'}")
        if labels:
            ctx.recon["zap_alerts"] = sorted(set(ctx.recon.get("zap_alerts", []) + labels))[:500]
        urls = urls_payload.get("urls", [])
        if isinstance(urls, list) and urls:
            ctx.recon["site_map"] = sorted(set(ctx.recon.get("site_map", []) + [str(item) for item in urls]))[:1200]

    def _parse_zap_alerts(self, ctx: ScanContext, alerts: list[Any]) -> list[Finding]:
        findings: list[Finding] = []
        seen: dict[str, Finding] = {}
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            title = str(alert.get("alert") or alert.get("name") or "ZAP alert").strip()
            risk = str(alert.get("risk") or alert.get("riskdesc") or "Informational")
            severity = self._zap_severity(risk)
            confidence = self._zap_confidence(str(alert.get("confidence") or "medium"))
            url = str(alert.get("url") or ctx.target.url)
            plugin_id = str(alert.get("pluginId") or alert.get("alertRef") or "")
            if self._is_unconfirmed_zap_sqli_host(alert, plugin_id, confidence):
                label = (
                    f"Filtered unconfirmed ZAP SQLi Host-header variance @ {url} | "
                    f"attack={clean_text(alert.get('attack') or '', 160)}"
                )
                ctx.recon["zap_filtered_alerts"] = sorted(
                    set(ctx.recon.get("zap_filtered_alerts", []) + [label])
                )[:300]
                continue
            host_redirect = plugin_id == "20019" and str(alert.get("param") or "").strip().lower() in {
                "host",
                "host header",
                "http host",
            }
            url_key = url.lower() if severity in {"Critical", "High"} and not host_redirect else ""
            key = "|".join(
                [
                    title.lower(),
                    severity,
                    url_key,
                    str(alert.get("param") or "").lower(),
                    str(alert.get("attack") or "").lower(),
                    plugin_id,
                ]
            )
            if key in seen:
                existing = seen[key]
                if url and url != existing.url and url not in existing.details:
                    existing.details = " | ".join(
                        part for part in [existing.details, f"Affected URL: {url}"] if part
                    )
                continue
            cwe = self._zap_cwe(alert)
            evidence = self._zap_evidence(alert)
            finding = Finding(
                    target=ctx.target.display,
                    category="External/ZAP",
                    severity=severity,
                    title=f"ZAP: {title}",
                    url=url,
                    endpoint=urllib.parse.urlparse(url).path or "",
                    param=str(alert.get("param") or ""),
                    method=str(alert.get("method") or ""),
                    payload=str(alert.get("attack") or ""),
                    evidence=evidence,
                    source=f"zap:{plugin_id}" if plugin_id else "zap",
                    confidence=confidence,
                    cwe=cwe,
                    recommendation=clean_text(alert.get("solution") or "", 1600),
                    details=self._zap_details(alert),
            )
            findings.append(finding)
            seen[key] = finding
        return findings

    @staticmethod
    def _is_unconfirmed_zap_sqli_host(
        alert: dict[str, Any],
        plugin_id: str,
        confidence: str,
    ) -> bool:
        title = str(alert.get("alert") or alert.get("name") or "").lower()
        param = str(alert.get("param") or "").strip().lower()
        if plugin_id != "40018" and "sql" not in title:
            return False
        if param not in {"host", "host header", "http host"}:
            return False
        proof_text = " ".join(
            str(alert.get(key) or "")
            for key in ("evidence", "otherinfo", "otherInfo", "description")
        ).lower()
        database_errors = (
            "sql syntax",
            "sqlstate",
            "mysql",
            "postgresql",
            "sqlite",
            "ora-",
            "odbc",
            "unclosed quotation",
        )
        return confidence != "high" and not any(marker in proof_text for marker in database_errors)

    def _zap_severity(self, risk: str) -> str:
        lower = str(risk or "").lower()
        if "high" in lower:
            return "High"
        if "medium" in lower:
            return "Medium"
        if "low" in lower:
            return "Low"
        return "Info"

    def _zap_confidence(self, confidence: str) -> str:
        lower = str(confidence or "").lower()
        if "high" in lower:
            return "high"
        if "low" in lower:
            return "low"
        return "medium"

    def _zap_cwe(self, alert: dict[str, Any]) -> str:
        cwe = str(alert.get("cweid") or alert.get("cweId") or "").strip()
        if cwe and cwe not in {"0", "-1"}:
            return f"CWE-{cwe}" if cwe.isdigit() else cwe
        return ""

    def _zap_evidence(self, alert: dict[str, Any]) -> str:
        parts = [
            f"Risk={alert.get('risk') or alert.get('riskdesc') or '-'}",
            f"Confidence={alert.get('confidence') or '-'}",
            f"Evidence={alert.get('evidence') or '-'}",
            f"Param={alert.get('param') or '-'}",
            f"Attack={alert.get('attack') or '-'}",
            f"Plugin={alert.get('pluginId') or alert.get('alertRef') or '-'}",
        ]
        return clean_text(" | ".join(parts), 1400)

    def _zap_details(self, alert: dict[str, Any]) -> str:
        fields = [
            ("Description", alert.get("description")),
            ("Other Info", alert.get("otherinfo") or alert.get("otherInfo")),
            ("Reference", alert.get("reference")),
            ("WASC", alert.get("wascid") or alert.get("wascId")),
        ]
        return " | ".join(f"{key}: {clean_text(value, 900)}" for key, value in fields if value)

    def _write_ffuf_wordlist(self, ctx: ScanContext) -> Path:
        smart = [
            "",
            "login/",
            "login",
            "dashboard/",
            "dashboard",
            "admin/",
            "api/",
            "api/v1/",
            "swagger/",
            "swagger.json",
            "openapi.json",
            "graphql",
            "robots.txt",
            "sitemap.xml",
            ".well-known/security.txt",
            ".well-known/openid-configuration",
            ".git/config",
            ".env",
            "server-status",
            "server-status/",
            "metrics",
            "health",
            "debug/",
            "static/",
            "static/js/",
            "static/CSS/",
            "static/image/",
            "static/admin/",
            "javascript/",
            "saml/login/",
            "saml/metadata/",
            "saml/acs/",
            "logout/",
            "password_reset/",
        ]
        values: list[str] = []
        seen: set[str] = set()
        rutas = list(ctx.wordlists.get("rutas", []))
        if self.config.ffuf_max_words > 0:
            rutas = rutas[: self.config.ffuf_max_words]
        for raw in smart + rutas:
            clean = str(raw or "").strip()
            if clean.startswith(("http://", "https://")):
                clean = urllib.parse.urlparse(clean).path or "/"
            clean = clean.lstrip("/")
            if not clean:
                clean = ""
            if any(char in clean for char in ["\x00", "\r", "\n"]):
                continue
            if len(clean) > 220:
                continue
            key = clean.lower()
            if key not in seen:
                seen.add(key)
                values.append(clean)
        path = Path(tempfile.gettempdir()) / f"scan_titan_ffuf_{self._slug(ctx.target.display)}.txt"
        path.write_text("\n".join(values) + "\n", encoding="utf-8")
        return path

    async def _ffuf_soft404_signature(self, ctx: ScanContext) -> dict[str, Any]:
        """Measure a catch-all response with multiple non-existent routes."""
        samples: list[dict[str, Any]] = []
        origin = self._origin_url(ctx.target.url)
        for index in range(3):
            marker = f"scan-titan-soft404-{uuid.uuid4().hex}-{index}"
            url = urllib.parse.urljoin(origin, marker)
            result = await ctx.http.request(
                "GET",
                url,
                allow_redirects=False,
                timeout=min(ctx.limits.timeout, 8),
            )
            if not result or int(result.status or 0) == 404 or int(result.body_len or 0) <= 0:
                continue
            location = next(
                (str(value) for key, value in (result.headers or {}).items() if str(key).lower() == "location"),
                "",
            )
            text = str(result.text or "")
            samples.append(
                {
                    "status": int(result.status or 0),
                    "size": int(result.body_len or 0),
                    "words": len(re.findall(r"\S+", text)),
                    "lines": max(1, len(text.splitlines())),
                    "redirect_shape": self._redirect_shape(location),
                }
            )
        if len(samples) < 2 or len({item["status"] for item in samples}) != 1:
            return {}
        sizes = sorted(int(item["size"]) for item in samples)
        midpoint = sizes[len(sizes) // 2]
        tolerance = max(4, int(midpoint * 0.02))
        signature = {
            "status": samples[0]["status"],
            "size_min": min(sizes),
            "size_max": max(sizes),
            "size_tolerance": tolerance,
            "words": samples[0]["words"] if len({item["words"] for item in samples}) == 1 else None,
            "lines": samples[0]["lines"] if len({item["lines"] for item in samples}) == 1 else None,
            "redirect_shape": (
                samples[0]["redirect_shape"]
                if samples[0]["redirect_shape"] and len({item["redirect_shape"] for item in samples}) == 1
                else ""
            ),
            "samples": len(samples),
        }
        ctx.recon["ffuf_soft404_signature"] = signature
        return signature

    def _ffuf_filter_args(self, signature: dict[str, Any]) -> list[str]:
        if not signature:
            return []
        filters: list[str] = []
        size_min = int(signature.get("size_min") or 0)
        size_max = int(signature.get("size_max") or 0)
        tolerance = int(signature.get("size_tolerance") or 0)
        if size_min > 0 and size_max - size_min <= max(8, tolerance * 2):
            filters.extend(["-fs", f"{max(1, size_min - tolerance)}-{size_max + tolerance}"])
        if signature.get("words") is not None:
            filters.extend(["-fw", str(signature["words"])])
        if signature.get("lines") not in {None, 1}:
            filters.extend(["-fl", str(signature["lines"])])
        criteria = sum(1 for item in ("-fs", "-fw", "-fl") if item in filters)
        if criteria >= 2:
            filters.extend(["-fmode", "and"])
        elif criteria == 0:
            return []
        return filters

    @staticmethod
    def _redirect_shape(value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        parsed = urllib.parse.urlsplit(text)
        query_keys = sorted(key.lower() for key, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        path = re.sub(r"/+", "/", parsed.path or "/").rstrip("/") or "/"
        return f"{path.lower()}?{','.join(query_keys)}"

    def _ffuf_matches_soft404(self, item: dict[str, Any], signature: dict[str, Any]) -> bool:
        if not signature or int(item.get("status") or 0) != int(signature.get("status") or -1):
            return False
        redirect = item.get("redirectlocation") or item.get("redirect-location") or ""
        expected_redirect = str(signature.get("redirect_shape") or "")
        if expected_redirect and self._redirect_shape(redirect) == expected_redirect:
            return True
        size = int(item.get("length") or 0)
        tolerance = int(signature.get("size_tolerance") or 0)
        size_matches = (
            size > 0
            and int(signature.get("size_min") or 0) - tolerance
            <= size
            <= int(signature.get("size_max") or 0) + tolerance
        )
        comparisons = [size_matches]
        if signature.get("words") is not None:
            comparisons.append(int(item.get("words") or -1) == int(signature["words"]))
        if signature.get("lines") is not None:
            comparisons.append(int(item.get("lines") or -1) == int(signature["lines"]))
        return sum(bool(value) for value in comparisons) >= 2

    async def _whatweb_supports_official_flags(self, binary: str) -> bool:
        cached = self._whatweb_official_cache.get(binary)
        if cached is not None:
            return cached
        supported = False
        try:
            stdout, stderr, timed_out, returncode, _duration = await self._run_command(
                [binary, "--help"],
                min(12, max(5, self.config.whatweb_timeout)),
            )
            text = f"{stdout}\n{stderr}"
            supported = (
                not timed_out
                and returncode in {0, None}
                and "--log-json" in text
                and "--aggression" in text
            )
        except Exception:
            supported = False
        self._whatweb_official_cache[binary] = supported
        if not supported:
            Console.warn("Official WhatWeb JSON flags not available; using compatibility fingerprint mode")
        return supported

    def _whatweb_command(
        self,
        binary: str,
        ctx: ScanContext,
        export_path: Path,
        *,
        official_mode: bool,
    ) -> list[str]:
        if not official_mode:
            return [binary, ctx.target.url]
        return [
            binary,
            f"--aggression={self.config.whatweb_aggression}",
            f"--follow-redirect={self.config.whatweb_follow_redirect}",
            f"--max-redirects={self.config.whatweb_max_redirects}",
            f"--open-timeout={self.config.whatweb_open_timeout}",
            f"--read-timeout={self.config.whatweb_read_timeout}",
            f"--max-threads={self.config.whatweb_max_threads}",
            "--colour=never",
            "--no-errors",
            f"--log-json={export_path}",
            ctx.target.url,
        ]

    def _parse_whatweb(self, ctx: ScanContext, stdout: str, export_path: Path | None = None) -> list[Finding]:
        records = self._load_whatweb_json(export_path)
        if records:
            technologies = self._whatweb_json_technologies(records)
            evidence = self._whatweb_evidence(technologies, source="official-json")
            status = "OK"
        else:
            text = clean_text(stdout, 2200)
            if not text:
                return []
            technologies = self._whatweb_text_technologies(text)
            evidence = self._whatweb_evidence(technologies, source="compat-text") or text
            status = "TEXT_ONLY"
        if not technologies:
            return []
        self._merge_whatweb_recon(ctx, technologies, status=status, evidence=evidence)
        return [
            Finding(
                target=ctx.target.display,
                category="External/WhatWeb",
                severity="Info",
                title="WhatWeb technology fingerprint collected",
                url=ctx.target.url,
                evidence=clean_text(evidence, 1600),
                source="whatweb",
                confidence="high" if records else "medium",
            )
        ]

    def _load_whatweb_json(self, export_path: Path | None) -> list[dict[str, Any]]:
        if not export_path or not export_path.exists() or export_path.stat().st_size <= 2:
            return []
        try:
            parsed = json.loads(export_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception as exc:
            Console.warn(f"WhatWeb JSON could not be parsed: {clean_text(exc, 180)}")
            return []
        if isinstance(parsed, dict):
            return [parsed]
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        return []

    def _whatweb_json_technologies(self, records: list[dict[str, Any]]) -> list[dict[str, str]]:
        technologies: list[dict[str, str]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for record in records:
            plugins = record.get("plugins") if isinstance(record.get("plugins"), dict) else {}
            for plugin_name, plugin_data in plugins.items():
                name = clean_text(plugin_name, 120)
                if not name:
                    continue
                category = self._whatweb_category(name)
                values = plugin_data if isinstance(plugin_data, dict) else {}
                versions = self._whatweb_values(values.get("version") or values.get("versions"))
                strings = self._whatweb_values(values.get("string") or values.get("strings"))
                os_values = self._whatweb_values(values.get("os"))
                modules = self._whatweb_values(values.get("module") or values.get("modules"))
                certainty = self._whatweb_values(values.get("certainty"))
                version = ", ".join(versions[:3])
                evidence_parts = []
                if strings:
                    evidence_parts.append("string=" + ", ".join(strings[:3]))
                if os_values:
                    evidence_parts.append("os=" + ", ".join(os_values[:2]))
                if modules:
                    evidence_parts.append("module=" + ", ".join(modules[:3]))
                if certainty:
                    evidence_parts.append("certainty=" + ", ".join(certainty[:2]))
                evidence = "; ".join(evidence_parts)
                key = (category.casefold(), name.casefold(), version.casefold(), evidence.casefold())
                if key in seen:
                    continue
                seen.add(key)
                technologies.append(
                    {
                        "category": category,
                        "name": name,
                        "version": version,
                        "evidence": clean_text(evidence, 350),
                    }
                )
        return self._sort_whatweb_technologies(technologies)

    def _whatweb_text_technologies(self, text: str) -> list[dict[str, str]]:
        technologies: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for match in re.finditer(r"(?:^|,\s+)(?P<name>[A-Za-z][A-Za-z0-9_.+-]+)(?:\[(?P<value>[^\]]+)\])?", text):
            name = clean_text(match.group("name"), 120)
            value = clean_text(match.group("value") or "", 220)
            lower = name.casefold()
            if lower in {"http", "https", "ok", "moved", "permanently", "forbidden", "found"}:
                continue
            if "://" in name or len(name) < 2:
                continue
            category = self._whatweb_category(name)
            version = ""
            evidence = value
            version_match = re.search(r"\b\d+(?:\.\d+){1,3}[A-Za-z0-9._-]*\b", value)
            if version_match:
                version = version_match.group(0)
            key = (category.casefold(), name.casefold(), version.casefold())
            if key in seen:
                continue
            seen.add(key)
            technologies.append({"category": category, "name": name, "version": version, "evidence": evidence})
        return self._sort_whatweb_technologies(technologies)

    def _whatweb_values(self, value: Any) -> list[str]:
        values: list[str] = []
        if isinstance(value, dict):
            iterable: Any = value.values()
        elif isinstance(value, (list, tuple, set)):
            iterable = value
        elif value in (None, ""):
            iterable = []
        else:
            iterable = [value]
        for item in iterable:
            if isinstance(item, (list, tuple, set)):
                values.extend(self._whatweb_values(item))
                continue
            if isinstance(item, dict):
                values.extend(self._whatweb_values(item))
                continue
            text = clean_text(item, 180)
            if text and text.casefold() not in {"nil", "none", "null"}:
                values.append(text)
        return list(dict.fromkeys(values))

    def _whatweb_category(self, plugin_name: str) -> str:
        lower = plugin_name.casefold()
        if any(token in lower for token in ("apache", "nginx", "iis", "httpserver", "openresty", "tomcat", "jetty")):
            return "Web Server"
        if any(token in lower for token in ("cloudflare", "akamai", "fastly", "imperva", "sucuri", "incapsula", "varnish")):
            return "CDN/WAF/Proxy"
        if any(token in lower for token in ("jquery", "react", "angular", "vue", "bootstrap", "script", "javascript")):
            return "JavaScript/UI"
        if any(token in lower for token in ("wordpress", "drupal", "joomla", "moodle", "liferay", "cms")):
            return "CMS"
        if any(token in lower for token in ("php", "asp", "django", "laravel", "rails", "flask", "express", "framework")):
            return "Framework/Language"
        if any(token in lower for token in ("strict-transport", "x-frame", "content-security", "cookie", "httponly")):
            return "Security/Header"
        if any(token in lower for token in ("title", "html", "doctype", "country", "ip", "email")):
            return "Metadata"
        return "Technology"

    def _sort_whatweb_technologies(self, technologies: list[dict[str, str]]) -> list[dict[str, str]]:
        category_rank = {
            "Web Server": 0,
            "Framework/Language": 1,
            "CMS": 2,
            "JavaScript/UI": 3,
            "CDN/WAF/Proxy": 4,
            "Security/Header": 5,
            "Technology": 6,
            "Metadata": 7,
        }
        return sorted(
            technologies,
            key=lambda item: (
                category_rank.get(str(item.get("category", "")), 99),
                str(item.get("name", "")).casefold(),
                str(item.get("version", "")).casefold(),
            ),
        )

    def _whatweb_label(self, item: dict[str, str]) -> str:
        name = str(item.get("name") or "").strip()
        version = str(item.get("version") or "").strip()
        category = str(item.get("category") or "").strip()
        evidence = str(item.get("evidence") or "").strip()
        label = f"{name} {version}".strip()
        if category:
            label = f"{category}: {label}"
        if evidence:
            label = f"{label} ({clean_text(evidence, 120)})"
        return label

    def _whatweb_evidence(self, technologies: list[dict[str, str]], *, source: str) -> str:
        labels = [self._whatweb_label(item) for item in technologies[:40]]
        return f"WhatWeb {source}; technologies={len(technologies)}; " + " | ".join(labels)

    def _merge_whatweb_recon(
        self,
        ctx: ScanContext,
        technologies: list[dict[str, str]],
        *,
        status: str,
        evidence: str,
    ) -> None:
        labels = [self._whatweb_label(item) for item in technologies if item.get("name")]
        servers = [
            self._whatweb_label(item)
            for item in technologies
            if str(item.get("category", "")).casefold() in {"web server", "cdn/waf/proxy"}
        ]
        frameworks = [
            self._whatweb_label(item)
            for item in technologies
            if str(item.get("category", "")).casefold() in {"framework/language", "cms", "javascript/ui"}
        ]
        categories = [str(item.get("category", "")).strip() for item in technologies if item.get("category")]
        ctx.recon["whatweb_technologies"] = technologies
        ctx.recon["whatweb_status"] = status
        ctx.recon["whatweb_evidence"] = clean_text(evidence, 1800)
        ctx.recon["whatweb_categories"] = list(dict.fromkeys(categories))
        ctx.recon["whatweb_servers"] = list(dict.fromkeys(servers))
        ctx.recon["whatweb_frameworks"] = list(dict.fromkeys(frameworks))
        ctx.recon["technologies"] = self._merge_recon_values(ctx.recon.get("technologies", []), labels)[:400]

    def _merge_recon_values(self, existing: Any, incoming: list[str]) -> list[str]:
        values: list[str] = []
        seen: set[str] = set()
        if isinstance(existing, str):
            source_values = re.split(r"\s*\|\s*|\n+", existing)
        elif isinstance(existing, (list, tuple, set)):
            source_values = list(existing)
        else:
            source_values = []
        for item in [*source_values, *incoming]:
            clean = clean_text(item, 350)
            key = clean.casefold()
            if clean and key not in seen:
                seen.add(key)
                values.append(clean)
        return sorted(values, key=lambda value: value.casefold())

    async def _whatweb_fallback(self, ctx: ScanContext, stderr: str) -> list[Finding]:
        result = await ctx.http.request("GET", ctx.target.url, allow_redirects=True, timeout=min(ctx.limits.timeout, 10))
        if not result:
            return []
        technologies = []
        server = result.headers.get("Server") or result.headers.get("server") or ""
        powered = result.headers.get("X-Powered-By") or result.headers.get("x-powered-by") or ""
        if server:
            technologies.append({"category": "Web Server", "name": "HTTPServer", "version": "", "evidence": server})
        if powered:
            technologies.append({"category": "Framework/Language", "name": "X-Powered-By", "version": "", "evidence": powered})
        lower = result.text.lower()
        markers = {
            "Django": ["csrfmiddlewaretoken", "django"],
            "Bootstrap": ["bootstrap"],
            "jQuery": ["jquery"],
            "HTMX": ["htmx"],
            "Alpine.js": ["alpine"],
            "SAML": ["/saml/login", "samlrequest"],
        }
        for name, needles in markers.items():
            if any(needle in lower for needle in needles):
                technologies.append({"category": self._whatweb_category(name), "name": name, "version": "", "evidence": "HTML marker"})
        if technologies:
            technologies = self._sort_whatweb_technologies(technologies)
            evidence = self._whatweb_evidence(technologies, source="fallback-http")
            self._merge_whatweb_recon(ctx, technologies, status="FALLBACK_HTTP", evidence=evidence)
        else:
            evidence = clean_text(stderr, 400) or "HTTP fingerprint fallback executed"
        return [
            Finding(
                target=ctx.target.display,
                category="External/WhatWeb",
                severity="Info",
                title="HTTP technology fingerprint collected by fallback",
                url=ctx.target.url,
                status=str(result.status),
                size=f"{result.body_len}b",
                evidence=clean_text(evidence, 1000),
                source="whatweb:fallback",
                confidence="medium",
            )
        ]

    def _parse_subfinder(self, ctx: ScanContext, stdout: str) -> list[Finding]:
        subdomains = []
        for line in stdout.splitlines():
            clean = line.strip().lower()
            if not clean or clean.startswith("["):
                continue
            if re.fullmatch(r"[a-z0-9*_.-]+\.[a-z0-9.-]+", clean):
                subdomains.append(clean)
        subdomains = sorted(set(subdomains))
        if not subdomains:
            return []
        ctx.recon["subdomains"] = sorted(set(ctx.recon.get("subdomains", []) + subdomains))[:500]
        return [
            Finding(
                target=ctx.target.display,
                category="External/Subfinder",
                severity="Info",
                title="Passive subdomains discovered",
                url=ctx.target.url,
                evidence=clean_text(subdomains[:80], 1200),
                source="subfinder",
                confidence="medium",
            )
        ]

    def _parse_ffuf(
        self,
        ctx: ScanContext,
        export_path: Path,
        stdout: str,
        soft404_signature: dict[str, Any] | None = None,
    ) -> tuple[list[Finding], int]:
        items: list[dict[str, Any]] = []
        raw_count = 0
        if export_path.exists():
            try:
                data = json.loads(export_path.read_text(encoding="utf-8", errors="ignore") or "{}")
                if isinstance(data, dict):
                    raw_items = data.get("results") or []
                    if isinstance(raw_items, list):
                        raw_count = len(raw_items)
                        items.extend(
                            item
                            for item in raw_items[: self.MAX_FFUF_RECON_HITS]
                            if isinstance(item, dict)
                        )
            except Exception:
                pass
        if not items:
            for line in stdout.splitlines():
                clean = line.strip()
                if clean and not clean.startswith("["):
                    items.append({"input": {"FUZZ": clean}, "status": 200, "url": urllib.parse.urljoin(self._origin_url(ctx.target.url), clean)})
                    if len(items) >= self.MAX_FFUF_RECON_HITS:
                        break
            raw_count = len(items)
        hits: list[dict[str, Any]] = []
        route_labels: list[str] = []
        soft404_filtered_count = 0
        for item in items:
            input_data = item.get("input", {}) if isinstance(item.get("input"), dict) else {}
            raw_path = str(input_data.get("FUZZ") or item.get("path") or "")
            path = "/" + raw_path.lstrip("/")
            status = int(item.get("status") or 0)
            url = item.get("url") or urllib.parse.urljoin(self._origin_url(ctx.target.url), path)
            redirect = item.get("redirectlocation") or item.get("redirect-location") or ""
            classification = self._ffuf_classification(path, status, redirect)
            soft_filtered = classification == "soft_auth_redirect" or self._ffuf_matches_soft404(
                item,
                soft404_signature or {},
            )
            if soft_filtered:
                soft404_filtered_count += 1
                continue
            hit = {
                "target": ctx.target.display,
                "ip": ctx.target.ip,
                "module": "ffuf",
                "wordlist": "ffuf_smart+rutas",
                "method": "GET",
                "status": status,
                "url": url,
                "path": path,
                "redirect_location": redirect,
                "content_type": "",
                "size_bytes": item.get("length", ""),
                "time_seconds": "",
                "title": "",
                "classification": classification,
                "soft404_filtered": soft_filtered,
                "sensitive_marker": self._ffuf_sensitive(path, classification),
                "evidence_summary": (
                    f"classification={classification} | words={item.get('words', '')} | "
                    f"lines={item.get('lines', '')} | redirect={redirect or '-'}"
                ),
                "notes": "soft-auth redirect catch-all" if soft_filtered else "External FFUF hit",
            }
            hits.append(hit)
            label = f"{path} ({status} {classification})" + (f" -> {redirect}" if redirect else "")
            route_labels.append(label)
        ctx.recon["ffuf_soft404_filtered_count"] = int(
            ctx.recon.get("ffuf_soft404_filtered_count", 0) or 0
        ) + soft404_filtered_count
        if hits:
            ctx.recon["wordlist_path_hits"] = list(
                ctx.recon.get("wordlist_path_hits", []) + hits[: self.MAX_FFUF_RECON_HITS]
            )[: self.MAX_FFUF_RECON_HITS]
            ctx.recon["discovered_paths"] = sorted(set(ctx.recon.get("discovered_paths", []) + route_labels))[:1200]
            ctx.recon["unauthenticated_routes"] = sorted(set(ctx.recon.get("unauthenticated_routes", []) + route_labels))[:700]
        # FFUF only discovers attack surface. A route name or HTTP status is not
        # proof of a vulnerability, so all results stay in the Recon dashboard.
        return [], len(hits)

    def _ffuf_classification(self, path: str, status: int, redirect: str) -> str:
        lower = path.lower()
        redirect_lower = str(redirect or "").lower()
        if status in {301, 302, 307, 308}:
            if "samlrequest=" in redirect_lower:
                return "saml_login_redirect"
            if redirect in {"/", "./"} or "login" in redirect_lower:
                if not is_authentication_url(path):
                    return "soft_auth_redirect"
                return "redirect_to_login"
            return "redirect"
        if status == 401:
            return "auth_required"
        if status == 403:
            return "forbidden"
        if status == 405:
            return "method_not_allowed"
        if lower.endswith((".save", ".bak", ".backup", ".old", ".orig", ".tmp", "~", ".swp")):
            return "static_residue"
        if lower.startswith("/static/"):
            return "static_asset_or_listing"
        if "saml/metadata" in lower:
            return "saml_metadata"
        if status == 200:
            return "public_200"
        return "http_hit"

    def _ffuf_sensitive(self, path: str, classification: str) -> bool:
        lower = path.lower()
        if classification in {"forbidden", "auth_required", "method_not_allowed", "static_residue", "saml_metadata"}:
            return True
        if classification == "soft_auth_redirect":
            return False
        return any(
            token in lower
            for token in [
                ".git",
                ".env",
                "admin",
                "server-status",
                "debug",
                "metrics",
                "actuator",
                "swagger",
                "openapi",
                "graphql",
                "backup",
                "config",
            ]
        )

    async def _run_command(self, cmd: list[str], timeout: int) -> tuple[str, str, bool, int | None, float]:
        started = time.monotonic()
        process: asyncio.subprocess.Process | None = None
        try:
            process_kwargs: dict[str, Any] = {}
            if os.name == "nt":
                process_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                process_kwargs["start_new_session"] = True
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **process_kwargs,
            )
            stdout_buffer: bytearray = bytearray()
            stderr_buffer: bytearray = bytearray()
            stream_stats: dict[str, Any] = {
                "stdout": 0,
                "stderr": 0,
                "last_activity": started,
                "last_output": "",
            }
            stdout_task = asyncio.create_task(
                self._read_stream_limited(process.stdout, stdout_buffer, stream_stats, "stdout")
            )
            stderr_task = asyncio.create_task(
                self._read_stream_limited(process.stderr, stderr_buffer, stream_stats, "stderr")
            )
            wait_task = asyncio.create_task(process.wait())
            hard_timeout = max(0, int(timeout or 0))
            deadline = started + hard_timeout if hard_timeout > 0 else None
            next_heartbeat = started + 15.0
            try:
                while True:
                    if self.config.runtime_control.finish_requested:
                        with contextlib.suppress(Exception):
                            await self._terminate_process_tree(process, force=False)
                        await self._finish_wait_task(wait_task)
                        await self._finish_stream_tasks(stdout_task, stderr_task)
                        extra = b"\nScan Titan graceful finish requested; subprocess terminated."
                        return (
                            bytes(stdout_buffer).decode(errors="replace"),
                            (bytes(stderr_buffer) + extra).decode(errors="replace"),
                            False,
                            process.returncode,
                            time.monotonic() - started,
                        )
                    now = time.monotonic()
                    if deadline is not None and now >= deadline:
                        with contextlib.suppress(Exception):
                            await self._terminate_process_tree(process, force=False)
                        await self._finish_wait_task(wait_task)
                        await self._finish_stream_tasks(stdout_task, stderr_task)
                        return (
                            bytes(stdout_buffer).decode(errors="replace"),
                            bytes(stderr_buffer).decode(errors="replace"),
                            True,
                            process.returncode,
                            time.monotonic() - started,
                        )
                    if now >= next_heartbeat:
                        elapsed = now - started
                        output_bytes = int(stream_stats.get("stdout", 0)) + int(stream_stats.get("stderr", 0))
                        idle_seconds = max(0.0, now - float(stream_stats.get("last_activity", started)))
                        mode = "sin limite" if deadline is None else f"limite={hard_timeout}s"
                        detail = (
                            f"proceso externo activo | {mode} | salida={output_bytes}b | "
                            f"sin_salida={idle_seconds:.0f}s"
                        )
                        last_output = clean_text(stream_stats.get("last_output", ""), 90)
                        if last_output:
                            detail = f"{detail} | ultimo={last_output}"
                        Console.heartbeat(Path(cmd[0]).name, detail, int(elapsed), output_bytes)
                        if self.config.telemetry:
                            self.config.telemetry.external_heartbeat(
                                process.pid,
                                elapsed,
                            )
                        next_heartbeat = now + 15.0
                    done, _pending = await asyncio.wait(
                        {wait_task},
                        timeout=1.0,
                    )
                    if wait_task in done:
                        await wait_task
                        await self._finish_stream_tasks(stdout_task, stderr_task)
                        return (
                            bytes(stdout_buffer).decode(errors="replace"),
                            bytes(stderr_buffer).decode(errors="replace"),
                            False,
                            process.returncode,
                            time.monotonic() - started,
                        )
            except asyncio.CancelledError:
                with contextlib.suppress(Exception):
                    await self._terminate_process_tree(process, force=False)
                await self._finish_wait_task(wait_task)
                await self._finish_stream_tasks(stdout_task, stderr_task)
                raise
            except KeyboardInterrupt:
                with contextlib.suppress(Exception):
                    await self._terminate_process_tree(process, force=False)
                await self._finish_wait_task(wait_task)
                await self._finish_stream_tasks(stdout_task, stderr_task)
                raise
        except Exception as exc:
            return "", str(exc), False, -1, time.monotonic() - started

    async def _collect_process_output(self, process: asyncio.subprocess.Process) -> tuple[bytes, bytes]:
        stdout_task = asyncio.create_task(self._read_stream_limited(process.stdout))
        stderr_task = asyncio.create_task(self._read_stream_limited(process.stderr))
        await process.wait()
        return await stdout_task, await stderr_task

    async def _read_stream_limited(
        self,
        stream: asyncio.StreamReader | None,
        kept: bytearray | None = None,
        stats: dict[str, Any] | None = None,
        channel: str = "stdout",
    ) -> bytes:
        if stream is None:
            return b""
        buffer = kept if kept is not None else bytearray()
        discarded = 0
        try:
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    break
                if stats is not None:
                    stats[channel] = int(stats.get(channel, 0)) + len(chunk)
                    stats["last_activity"] = time.monotonic()
                    last_line = chunk.decode(errors="replace").strip().splitlines()
                    if last_line:
                        stats["last_output"] = last_line[-1]
                remaining = self.MAX_EXTERNAL_OUTPUT_BYTES - len(buffer)
                if remaining > 0:
                    buffer.extend(chunk[:remaining])
                discarded += max(0, len(chunk) - max(0, remaining))
        except (ConnectionResetError, OSError, ValueError) as exc:
            if stats is not None:
                stats["last_activity"] = time.monotonic()
                stats["last_output"] = f"stream cerrado: {clean_text(exc, 80)}"
        if discarded:
            buffer.extend(f"\n[Scan Titan truncated {discarded} output bytes]".encode())
        return bytes(buffer)

    async def _finish_stream_tasks(self, *tasks: asyncio.Task[bytes]) -> None:
        pending = [task for task in tasks if not task.done()]
        if not pending:
            return
        try:
            await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=5)
        except asyncio.TimeoutError:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    async def _finish_wait_task(self, wait_task: asyncio.Task[int]) -> None:
        if wait_task.done():
            with contextlib.suppress(Exception):
                await wait_task
            return
        try:
            await asyncio.wait_for(wait_task, timeout=5)
        except asyncio.TimeoutError:
            wait_task.cancel()
            await asyncio.gather(wait_task, return_exceptions=True)
        except Exception:
            pass

    async def _stop_process_with_task(
        self,
        process: asyncio.subprocess.Process,
        communicate_task: asyncio.Task[tuple[bytes, bytes]],
    ) -> tuple[bytes, bytes]:
        try:
            if process.returncode is None:
                await self._terminate_process_tree(process, force=False)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                if process.returncode is None:
                    await self._terminate_process_tree(process, force=True)
            except Exception:
                pass
        try:
            return await asyncio.wait_for(asyncio.shield(communicate_task), timeout=2)
        except asyncio.TimeoutError:
            try:
                if process.returncode is None:
                    await self._terminate_process_tree(process, force=True)
            except Exception:
                pass
            try:
                return await asyncio.wait_for(asyncio.shield(communicate_task), timeout=2)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                if not communicate_task.done():
                    communicate_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await communicate_task
                return b"", b""
            except Exception:
                return b"", b""
        except asyncio.CancelledError:
            if not communicate_task.done():
                communicate_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await communicate_task
            return b"", b""
        except Exception:
            if not communicate_task.done():
                communicate_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await communicate_task
            return b"", b""

    async def _terminate_process_tree(self, process: asyncio.subprocess.Process, *, force: bool) -> None:
        if process.returncode is not None:
            return
        if os.name == "nt":
            killer = await asyncio.create_subprocess_exec(
                "taskkill",
                "/PID",
                str(process.pid),
                "/T",
                "/F",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(killer.wait(), timeout=2)
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
            return
        sig = signal.SIGKILL if force else signal.SIGTERM
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, sig)

    async def _terminate_process(self, process: asyncio.subprocess.Process) -> tuple[bytes, bytes]:
        try:
            if process.returncode is None:
                await self._terminate_process_tree(process, force=False)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                if process.returncode is None:
                    await self._terminate_process_tree(process, force=True)
            except Exception:
                pass
        try:
            return await asyncio.wait_for(process.communicate(), timeout=5)
        except asyncio.TimeoutError:
            try:
                if process.returncode is None:
                    await self._terminate_process_tree(process, force=True)
            except Exception:
                pass
            try:
                return await asyncio.wait_for(process.communicate(), timeout=5)
            except asyncio.CancelledError:
                return b"", b""
            except Exception:
                return b"", b""
        except asyncio.CancelledError:
            return b"", b""
        except Exception:
            return b"", b""

    @staticmethod
    def _format_command(cmd: list[str]) -> str:
        parts: list[str] = []
        for raw_part in cmd:
            part = str(raw_part)
            if re.search(r"\s", part):
                part = '"' + part.replace('"', '\\"') + '"'
            parts.append(part)
        return " ".join(parts)

    def _log_external(
        self,
        tool: str,
        profile: str,
        cmd: list[str],
        returncode: int | None,
        timed_out: bool,
        stderr: str,
        stdout: str,
        export_path: Path | None = None,
        duration: float = 0.0,
        parsed_count: int = 0,
        empty_reason: str = "",
        target: str = "",
    ) -> None:
        if self.config.telemetry:
            self.config.telemetry.external_end(
                tool,
                profile,
                returncode,
                timed_out,
                duration,
                parsed_count,
                empty_reason or stderr,
            )
        try:
            log_path = REPORTS_DIR / "external_tools.log"
            export_info = ""
            if export_path is not None:
                size = export_path.stat().st_size if export_path.exists() else 0
                export_info = f" | export={export_path.name} size={size}"
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    f"[{now_text()}] {tool}:{profile} rc={returncode} timeout={timed_out}"
                    f" duration={duration:.1f}s parsed={parsed_count}{export_info}\n"
                )
                handle.write(f"  CMD: {' '.join(cmd)}\n")
                if stderr.strip():
                    handle.write(f"  STDERR: {clean_text(stderr, 800)}\n")
                if stdout.strip():
                    handle.write(f"  STDOUT: {clean_text(stdout, 800)}\n")
                if empty_reason:
                    handle.write(f"  EMPTY_REASON: {empty_reason}\n")
            if self.config.policy.external_observability:
                self._write_observability_event(
                    tool=tool,
                    profile=profile,
                    cmd=cmd,
                    returncode=returncode,
                    timed_out=timed_out,
                    stderr=stderr,
                    stdout=stdout,
                    export_path=export_path,
                    duration=duration,
                    parsed_count=parsed_count,
                    empty_reason=empty_reason,
                    target=target,
                )
        except Exception:
            pass

    def _write_observability_event(
        self,
        *,
        tool: str,
        profile: str,
        cmd: list[str],
        returncode: int | None,
        timed_out: bool,
        stderr: str,
        stdout: str,
        export_path: Path | None,
        duration: float,
        parsed_count: int,
        empty_reason: str,
        target: str,
    ) -> None:
        event = {
            "timestamp": now_text(),
            "tool": tool,
            "profile": profile,
            "target": target,
            "command": cmd,
            "returncode": returncode,
            "timed_out": timed_out,
            "duration_seconds": round(duration, 2),
            "parsed_findings": parsed_count,
            "export": str(export_path) if export_path else "",
            "export_size": export_path.stat().st_size if export_path and export_path.exists() else 0,
            "stderr_summary": clean_text(stderr, 1000),
            "stdout_summary": clean_text(stdout, 1000),
            "empty_reason": empty_reason,
            "nuclei_templates_loaded": self._extract_templates_loaded(stdout + "\n" + stderr),
        }
        jsonl = REPORTS_DIR / "external_tools_observability.jsonl"
        with jsonl.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        self._write_observability_html(jsonl)

    def _write_observability_html(self, jsonl: Path) -> None:
        try:
            rows = []
            for line in jsonl.read_text(encoding="utf-8", errors="ignore").splitlines()[-200:]:
                item = json.loads(line)
                rows.append(item)
            total = len(rows)
            failed = sum(1 for item in rows if item.get("returncode") not in {0, None} or item.get("timed_out"))
            useful = sum(1 for item in rows if int(item.get("parsed_findings") or 0) > 0)
            empty = sum(1 for item in rows if item.get("empty_reason"))
            tool_counts = Counter(str(item.get("tool", "-")) for item in rows)
            tool_summary = " | ".join(f"{html.escape(tool)}={count}" for tool, count in tool_counts.most_common())
            page = [
                "<!doctype html><meta charset='utf-8'><title>Scan Titan - Observabilidad de Herramientas Externas</title>",
                "<style>body{font-family:Segoe UI,Arial;background:#0f172a;color:#e5e7eb;padding:24px}"
                ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0}"
                ".card{background:#111827;border:1px solid #334155;border-radius:8px;padding:14px}.label{color:#94a3b8;font-size:12px;text-transform:uppercase}"
                ".value{font-size:26px;font-weight:700;margin-top:4px}.toolbar{margin:14px 0}"
                "input{width:100%;max-width:560px;background:#020617;color:#e5e7eb;border:1px solid #334155;border-radius:6px;padding:10px}"
                "table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #334155;padding:8px;vertical-align:top}"
                "th{background:#111827;color:white;position:sticky;top:0}.ok{color:#22c55e}.bad{color:#f87171}.warn{color:#fbbf24}"
                "code{white-space:pre-wrap;word-break:break-word;color:#bfdbfe}</style>",
                "<h1>Scan Titan - Observabilidad de Herramientas Externas</h1>",
                f"<p>Ultimos {total} eventos externos. Herramientas: {tool_summary or '-'}</p>",
                "<div class='cards'>",
                f"<div class='card'><div class='label'>Eventos</div><div class='value'>{total}</div></div>",
                f"<div class='card'><div class='label'>Con hallazgos</div><div class='value ok'>{useful}</div></div>",
                f"<div class='card'><div class='label'>Errores/Timeout</div><div class='value bad'>{failed}</div></div>",
                f"<div class='card'><div class='label'>Sin resultado util</div><div class='value warn'>{empty}</div></div>",
                "</div>",
                "<div class='toolbar'><input id='q' placeholder='Filtrar por tool, perfil, error o comando...' oninput='filterRows()'></div>",
                "<table><thead><tr><th>Fecha</th><th>Objetivo</th><th>Herramienta</th><th>Perfil</th><th>RC</th><th>Timeout</th>"
                "<th>Duracion</th><th>Parseados</th><th>Export</th><th>Razon sin hallazgos</th><th>Comando</th></tr></thead><tbody>",
            ]
            for item in rows:
                rc_class = "ok" if item.get("returncode") in {0, None} else "bad"
                row_text = " ".join(
                    str(item.get(key, ""))
                    for key in ("timestamp", "target", "tool", "profile", "returncode", "empty_reason")
                ) + " " + " ".join(item.get("command", []))
                page.append(
                    f"<tr data-search='{html.escape(row_text.lower())}'>"
                    f"<td>{html.escape(str(item.get('timestamp','')))}</td>"
                    f"<td>{html.escape(str(item.get('target','')))}</td>"
                    f"<td>{html.escape(str(item.get('tool','')))}</td>"
                    f"<td>{html.escape(str(item.get('profile','')))}</td>"
                    f"<td class='{rc_class}'>{item.get('returncode','')}</td>"
                    f"<td>{html.escape(str(item.get('timed_out','')))}</td>"
                    f"<td>{html.escape(str(item.get('duration_seconds','')))}</td>"
                    f"<td>{html.escape(str(item.get('parsed_findings','')))}</td>"
                    f"<td>{html.escape(Path(item.get('export','')).name if item.get('export') else '')} ({item.get('export_size',0)}b)</td>"
                    f"<td>{html.escape(clean_text(item.get('empty_reason',''), 260))}</td>"
                    f"<td><code>{html.escape(clean_text(' '.join(item.get('command', [])), 520))}</code></td>"
                    "</tr>"
                )
            page.append(
                "</tbody></table><script>"
                "function filterRows(){const q=document.getElementById('q').value.toLowerCase();"
                "document.querySelectorAll('tbody tr').forEach(r=>{r.style.display=r.dataset.search.includes(q)?'':'none';});}"
                "</script>"
            )
            (REPORTS_DIR / "External_Tools_Observability.html").write_text("\n".join(page), encoding="utf-8")
        except Exception as exc:
            Console.warn(f"No se pudo escribir la observabilidad HTML de herramientas externas: {exc}")

    def _empty_reason(
        self,
        returncode: int | None,
        timed_out: bool,
        stderr: str,
        stdout: str,
        export_path: Path | None,
        parsed_count: int,
    ) -> str:
        if parsed_count:
            return ""
        if timed_out:
            return "La ejecucion agoto el timeout antes de parsear salida util."
        if returncode not in {0, None}:
            return f"La herramienta finalizo con codigo de salida no cero {returncode}."
        if export_path and (not export_path.exists() or export_path.stat().st_size == 0):
            return "El archivo JSON de exportacion no fue creado o quedo vacio."
        text = (stdout + "\n" + stderr).lower()
        if "no results found" in text or "no templates provided" in text:
            return "La herramienta no reporto coincidencias o plantillas utilizables."
        if "cloudflare" in text or "rate-limit" in text or "429" in text:
            return "Posible rate-limit del objetivo o interferencia de WAF."
        return "El comando finalizo, pero el parser no identifico hallazgos utiles."

    def _extract_templates_loaded(self, text: str) -> int | None:
        patterns = [
            r"templates\s+loaded[^0-9]*(\d+)",
            r"loaded\s+templates[^0-9]*(\d+)",
            r"templates\s*:\s*(\d+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                return int(match.group(1))
        return None

    def _parse_nmap(self, ctx: ScanContext, xml_text: str, profile: str = "nmap") -> list[Finding]:
        ports: list[str] = []
        services: list[str] = []
        ports_services: list[str] = []
        script_notes: list[str] = []
        findings: list[Finding] = []
        if not xml_text.strip():
            return []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")
            service = port.find("service")
            service_name = service.get("name", "?") if service is not None else "?"
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            ports.append(f"{port_id}/{protocol}")
            service_text = " ".join(item for item in [service_name, product, version] if item)
            services.append(service_text)
            ports_services.append(f"{port_id}/{protocol}: {service_text}")
            for script in port.findall("script"):
                output = script.get("output", "")
                script_id = script.get("id", "script")
                if output:
                    script_notes.append(
                        f"{profile} {port_id}/{protocol} {script_id}: {clean_text(output, 350)}"
                    )
                    finding = self._nmap_script_finding(
                        ctx=ctx,
                        profile=profile,
                        port_id=port_id,
                        protocol=protocol,
                        service_text=service_text,
                        script_id=script_id,
                        output=output,
                    )
                    if finding:
                        findings.append(finding)
        ctx.recon["open_ports"] = sorted(set(ctx.recon.get("open_ports", []) + ports))
        ctx.recon["services"] = sorted(set(ctx.recon.get("services", []) + services))
        ctx.recon["ports_services"] = sorted(set(ctx.recon.get("ports_services", []) + ports_services))
        ctx.recon["nmap_scripts"] = sorted(set(ctx.recon.get("nmap_scripts", []) + script_notes))[:180]
        ctx.recon["nmap_profiles"] = sorted(set(ctx.recon.get("nmap_profiles", []) + [profile]))
        Console.ok(f"Nmap parseado ({profile}): {len(ports)} puerto(s) abierto(s), {len(findings)} hallazgo(s)")
        return findings

    def _nmap_script_finding(
        self,
        *,
        ctx: ScanContext,
        profile: str,
        port_id: str,
        protocol: str,
        service_text: str,
        script_id: str,
        output: str,
    ) -> Finding | None:
        if not self._script_looks_vulnerable(script_id, output):
            return None
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", output, flags=re.IGNORECASE)))
        scores = [float(match) for match in re.findall(r"\b(?:CVSS[:\s]*)?(10\.0|[0-9]\.[0-9])\b", output, flags=re.IGNORECASE)]
        max_score = max(scores) if scores else 0.0
        metadata = self._nmap_script_metadata(script_id, output)
        severity = metadata.get("severity") or self._severity_from_cvss(max_score, output)
        cve_text = ", ".join(cves[:8]) if cves else script_id
        if script_id.lower().strip() in {"vulners", "vulscan"}:
            title = f"Potential CVEs inferred from service version: {cve_text}"
        else:
            title = metadata.get("title") or cve_text
        cvss_text = metadata.get("cvss", "") or (self._cvss_text(max_score) if max_score else "")
        return Finding(
            target=ctx.target.display,
            category="External/Nmap",
            severity=severity,
            title=f"Nmap {profile}: {title} on {port_id}/{protocol}",
            endpoint=f"{port_id}/{protocol}",
            status=service_text,
            evidence=clean_text(output, 1200),
            source=f"nmap:{script_id}",
            confidence=metadata.get("confidence") or ("medium" if cves or max_score >= 5.0 else "low"),
            evidence_strength=metadata.get("evidence_strength", "Nmap NSE script output"),
            false_positive_risk=metadata.get("false_positive_risk", "Medium"),
            cwe=metadata.get("cwe", ""),
            owasp=metadata.get("owasp", ""),
            cvss=cvss_text,
            impact=metadata.get("impact", ""),
            remediation=metadata.get("remediation", ""),
            recommendation=metadata.get("recommendation") or self._nmap_recommendation(service_text, cves),
        )

    def _script_looks_vulnerable(self, script_id: str, output: str) -> bool:
        lower = f"{script_id} {output}".lower()
        output_lower = output.lower()
        negative_markers = [
            "no vulnerabilities found",
            "not vulnerable",
            "state: not_vulnerable",
            "couldn't find",
            "no cpe",
            "no vulnerable",
            "no weak",
        ]
        if any(marker in lower for marker in negative_markers):
            return False
        exposure_markers = {
            "http-git": ("git repository found", ".git/", ".git directory", "repository found"),
            "http-backup-finder": ("backup file found", "found backup", "200 ok"),
        }
        for script_name, markers in exposure_markers.items():
            if script_id.lower() == script_name and any(marker in output_lower for marker in markers):
                return True
        if script_id.lower() in {"ssl-dh-params", "ssl-enum-ciphers"} and any(
            marker in output_lower for marker in ("least strength: f", "weak", "anonymous", "export")
        ):
            return True
        positive_markers = [
            "cve-",
            "vulnerable",
            "likely vulnerable",
            "appears vulnerable",
            "vulnerability found",
            "state: likely vulnerable",
            "state: vulnerable",
            "exploit",
            "cvss",
            "anonymous access",
        ]
        return any(marker in lower for marker in positive_markers)

    def _nmap_script_metadata(self, script_id: str, output: str) -> dict[str, str]:
        sid = script_id.lower().strip()
        lower = output.lower()
        if sid in {"vulners", "vulscan"}:
            return {
                "severity": "Medium",
                "cvss": "5.3 (Medium)",
                "cwe": "CWE-1035",
                "owasp": "A03:2025 - Fallos en la cadena de suministro de software",
                "confidence": "medium",
                "evidence_strength": "Version/CPE correlation; vendor patch state unverified",
                "false_positive_risk": "Medium",
                "impact": "El banner coincide con versiones asociadas a CVE publicos, pero no confirma el estado real del paquete ni los backports del proveedor.",
                "remediation": "Validar el paquete instalado y su revision contra el boletin del proveedor; aplicar parches oficiales o documentar el backport antes de elevar la severidad.",
            }
        catalog: dict[str, dict[str, str]] = {
            "http-vuln-cve2011-3192": {
                "title": "Apache Range header denial-of-service CVE-2011-3192",
                "severity": "High",
                "cvss": "7.5 (High)",
                "cwe": "CWE-400",
                "owasp": "A06:2025 - Diseño inseguro",
                "confidence": "high",
                "evidence_strength": "Specific NSE CVE check",
                "false_positive_risk": "Low",
                "impact": "Un manejo vulnerable de cabeceras Range puede consumir recursos del servidor y provocar denegacion de servicio.",
                "remediation": "Actualizar Apache/paquetes del proveedor, bloquear rangos multiples anómalos en proxy/WAF y validar que el script NSE ya no marque el servicio como vulnerable.",
            },
            "http-vuln-cve2015-1635": {
                "title": "Microsoft HTTP.sys remote code execution CVE-2015-1635",
                "severity": "Critical",
                "cvss": "10.0 (Critical)",
                "cwe": "CWE-119",
                "owasp": "A03:2025 - Fallos en la cadena de suministro de software",
                "confidence": "high",
                "evidence_strength": "Specific NSE CVE check",
                "false_positive_risk": "Low",
                "impact": "Una version vulnerable de HTTP.sys puede permitir ejecucion remota de codigo o denegacion de servicio mediante solicitudes HTTP especialmente construidas.",
                "remediation": "Aplicar MS15-034 o parches acumulativos equivalentes, reiniciar el servicio afectado y repetir validacion NSE.",
            },
            "ssl-heartbleed": {
                "title": "OpenSSL Heartbleed CVE-2014-0160",
                "severity": "High",
                "cvss": "7.5 (High)",
                "cwe": "CWE-200",
                "owasp": "A04:2025 - Fallos criptográficos",
                "confidence": "high",
                "evidence_strength": "Specific NSE TLS vulnerability check",
                "false_positive_risk": "Low",
                "impact": "El servicio TLS podria exponer memoria del proceso, incluyendo credenciales, cookies, claves privadas u otros datos sensibles.",
                "remediation": "Actualizar OpenSSL/libreria TLS, rotar certificados y secretos potencialmente expuestos, y repetir prueba Heartbleed.",
            },
            "ssl-ccs-injection": {
                "title": "OpenSSL CCS Injection CVE-2014-0224",
                "severity": "Medium",
                "cvss": "6.8 (Medium)",
                "cwe": "CWE-327",
                "owasp": "A04:2025 - Fallos criptográficos",
                "confidence": "high",
                "evidence_strength": "Specific NSE TLS vulnerability check",
                "false_positive_risk": "Low",
                "impact": "Un atacante en posicion de intermediario podria debilitar la negociacion TLS y comprometer la confidencialidad del canal.",
                "remediation": "Actualizar OpenSSL/libreria TLS, deshabilitar stacks legacy y validar nuevamente la negociacion criptografica.",
            },
            "ssl-poodle": {
                "title": "POODLE SSLv3 downgrade exposure",
                "severity": "Medium",
                "cvss": "5.9 (Medium)",
                "cwe": "CWE-327",
                "owasp": "A04:2025 - Fallos criptográficos",
                "confidence": "high",
                "evidence_strength": "NSE protocol downgrade check",
                "false_positive_risk": "Low",
                "impact": "La aceptacion de SSLv3 o cifrados CBC legacy facilita ataques de downgrade y recuperacion parcial de informacion cifrada.",
                "remediation": "Deshabilitar SSLv2/SSLv3 y cifrados legacy, forzar TLS 1.2/1.3 con suites modernas y activar HSTS cuando aplique.",
            },
            "sslv2": {
                "title": "SSLv2 protocol enabled",
                "severity": "Medium",
                "cvss": "5.9 (Medium)",
                "cwe": "CWE-327",
                "owasp": "A04:2025 - Fallos criptográficos",
                "confidence": "high",
                "evidence_strength": "NSE protocol support check",
                "false_positive_risk": "Low",
                "impact": "SSLv2 es criptograficamente obsoleto y puede permitir downgrade o exposicion de trafico sensible.",
                "remediation": "Deshabilitar SSLv2/SSLv3 en el servidor y balanceadores, mantener solo TLS moderno con suites fuertes.",
            },
            "ssl-dh-params": {
                "title": "Weak Diffie-Hellman parameters",
                "severity": "Medium",
                "cvss": "5.9 (Medium)",
                "cwe": "CWE-326",
                "owasp": "A04:2025 - Fallos criptográficos",
                "confidence": "medium",
                "evidence_strength": "NSE DH parameter analysis",
                "false_positive_risk": "Medium",
                "impact": "Parametros DH debiles o grupos reutilizados reducen la fortaleza efectiva del canal TLS.",
                "remediation": "Usar ECDHE moderno, parametros DH de al menos 2048 bits si son necesarios, y eliminar suites export/weak.",
            },
            "smb-vuln-ms17-010": {
                "title": "SMB MS17-010 EternalBlue exposure",
                "severity": "Critical",
                "cvss": "9.8 (Critical)",
                "cwe": "CWE-119",
                "owasp": "A03:2025 - Fallos en la cadena de suministro de software",
                "confidence": "high",
                "evidence_strength": "Specific SMB NSE check",
                "false_positive_risk": "Low",
                "impact": "El servicio SMB podria permitir ejecucion remota de codigo explotable de forma no autenticada en sistemas no parcheados.",
                "remediation": "Aplicar MS17-010/parches acumulativos, deshabilitar SMBv1, restringir 445/TCP por segmentacion y repetir validacion.",
            },
            "http-git": {
                "title": "Exposed Git repository over HTTP",
                "severity": "Medium",
                "cvss": "5.3 (Medium)",
                "cwe": "CWE-548",
                "owasp": "A02:2025 - Configuración de seguridad incorrecta",
                "confidence": "high",
                "evidence_strength": "Nmap http-git exposure check",
                "false_positive_risk": "Low",
                "impact": "La exposicion de .git puede permitir reconstruir codigo fuente, rutas internas, secretos historicos o logica sensible.",
                "remediation": "Bloquear .git y artefactos VCS desde el servidor web, retirar el directorio expuesto y rotar secretos filtrados.",
            },
        }
        if sid == "ssl-enum-ciphers" and any(marker in lower for marker in ("least strength: f", "weak", "anonymous", "export")):
            return {
                "title": "Weak TLS cipher or protocol detected",
                "severity": "Medium",
                "cvss": "5.9 (Medium)",
                "cwe": "CWE-327",
                "owasp": "A04:2025 - Fallos criptográficos",
                "confidence": "medium",
                "evidence_strength": "NSE cipher enumeration",
                "false_positive_risk": "Medium",
                "impact": "El servicio acepta suites criptograficas debiles o protocolos heredados que reducen la confidencialidad del canal.",
                "remediation": "Restringir TLS a 1.2/1.3, priorizar AEAD/ECDHE y eliminar suites NULL, anonimas, export, RC4, DES/3DES o CBC legacy cuando sea posible.",
            }
        return catalog.get(sid, {})

    def _severity_from_cvss(self, score: float, output: str) -> str:
        upper = output.upper()
        if score >= 9.0 or "CRITICAL" in upper:
            return "Critical"
        if score >= 7.0 or "HIGH" in upper or "EXPLOIT" in upper:
            return "High"
        if score >= 5.0 or "MEDIUM" in upper:
            return "Medium"
        return "Low"

    def _cvss_text(self, score: float) -> str:
        if score >= 9.0:
            label = "Critical"
        elif score >= 7.0:
            label = "High"
        elif score >= 4.0:
            label = "Medium"
        elif score > 0:
            label = "Low"
        else:
            label = "Info"
        return f"{score:.1f} ({label})"

    def _nmap_recommendation(self, service_text: str, cves: list[str]) -> str:
        lower = service_text.lower()
        cve_note = f" CVEs principales: {', '.join(cves[:6])}." if cves else ""
        if "apache" in lower or "httpd" in lower:
            return "Actualizar Apache HTTP Server al paquete corregido por el proveedor, validar modulos cargados y restringir exposicion del vhost afectado." + cve_note
        if "openssh" in lower or "ssh" in lower:
            return "Validar el paquete OpenSSH instalado contra los avisos del proveedor, aplicar parches de seguridad y restringir acceso SSH por red/VPN/ACL." + cve_note
        return "Validar la version exacta del servicio contra advisories del proveedor, aplicar parches y documentar excepciones con controles compensatorios." + cve_note

    def _nuclei_common_flags(self) -> list[str]:
        flags: list[str] = []
        if self.config.nuclei_system_resolvers:
            flags.append("-sr")
        if self.config.nuclei_disable_host_error_skip:
            flags.append("-nmhe")
        flags.append("-fhr")
        return flags

    def _nuclei_seed_urls(self, ctx: ScanContext) -> list[str]:
        """Return bounded, same-origin endpoints discovered before Nuclei runs."""
        candidates: list[Any] = [ctx.target.url, self._origin_url(ctx.target.url)]
        for key in (
            "endpoints",
            "site_map",
            "discovered_paths",
            "unauthenticated_routes",
            "login_forms",
            "forms",
            "browser_routes",
            "browser_login_routes",
            "exposed_files",
        ):
            candidates.extend(ctx.recon.get(key, []) or [])
        for item in ctx.recon.get("wordlist_path_hits", []) or []:
            if isinstance(item, dict) and not item.get("soft404_filtered"):
                candidates.append(item)

        seeds: list[str] = []
        seen: set[str] = set()
        static_suffixes = (
            ".avif", ".bmp", ".css", ".eot", ".gif", ".ico", ".jpeg", ".jpg",
            ".map", ".mp3", ".mp4", ".otf", ".pdf", ".png", ".svg", ".ttf",
            ".webm", ".webp", ".woff", ".woff2",
        )
        for item in candidates:
            raw = self._zap_url_from_recon_item(ctx, item)
            if isinstance(item, dict):
                raw = str(item.get("url") or item.get("action") or item.get("path") or raw)
            normalized = self._zap_normalize_seed(ctx, raw)
            if not normalized:
                continue
            parsed = urllib.parse.urlsplit(normalized)
            if parsed.path.lower().endswith(static_suffixes):
                continue
            normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
            key = normalized.casefold()
            if key in seen:
                continue
            seen.add(key)
            seeds.append(normalized)
            if len(seeds) >= self.config.nuclei_max_seed_urls:
                break
        return seeds or [ctx.target.url]

    def _write_nuclei_target_list(self, ctx: ScanContext, slug: str, stamp: str) -> Path:
        target_list = REPORTS_DIR / f"nuclei_targets_{slug}_{stamp}.txt"
        target_list.write_text("\n".join(self._nuclei_seed_urls(ctx)) + "\n", encoding="utf-8")
        return target_list

    def _resolve_nuclei_template_dirs(self, *relative_paths: str) -> list[Path]:
        configured = Path(self.config.nuclei_templates_path).expanduser()
        env_templates = os.environ.get("NUCLEI_TEMPLATES", "").strip()
        bases: list[Path] = []
        if env_templates:
            bases.append(Path(env_templates).expanduser())
        if configured.is_absolute():
            bases.append(configured)
        else:
            bases.extend([BASE_DIR / configured, Path.home() / configured, Path.cwd() / configured])

        resolved: list[Path] = []
        seen: set[str] = set()
        for base in bases:
            for relative in relative_paths:
                candidate = base / relative
                try:
                    if candidate.is_dir():
                        key = str(candidate.resolve()).casefold()
                        if key not in seen:
                            seen.add(key)
                            resolved.append(candidate.resolve())
                except OSError:
                    continue
        return resolved

    def _nuclei_cve_selector_args(self) -> list[str]:
        template_dirs = self._resolve_nuclei_template_dirs("http/cves", "network/cves", "cves")
        if template_dirs:
            args: list[str] = []
            for template_dir in template_dirs:
                args.extend(["-t", str(template_dir)])
            return args
        return ["-tags", "cve,cves"]

    def _nuclei_profiles(self, binary: str, ctx: ScanContext) -> list[tuple[str, list[str], Path]]:
        slug = self._slug(ctx.target.display)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = REPORTS_DIR / f"nuclei_out_{slug}_{stamp}_vulnerabilities.jsonl"
        conservative_output = REPORTS_DIR / f"nuclei_out_{slug}_{stamp}_conservative.jsonl"
        cve_output = REPORTS_DIR / f"nuclei_out_{slug}_{stamp}_cves.jsonl"
        common_flags = self._nuclei_common_flags()
        cve_selector_args = self._nuclei_cve_selector_args()
        target_list = self._write_nuclei_target_list(ctx, slug, stamp)
        target_args = ["-l", str(target_list)]
        return [
            (
                "vulnerability_scan",
                [
                    binary,
                    *common_flags,
                    *target_args,
                    "-severity",
                    "low,medium,high,critical",
                    "-rl",
                    "35",
                    "-c",
                    "10",
                    "-timeout",
                    "12",
                    "-retries",
                    "1",
                    "-stats",
                    "-si",
                    "5",
                    "-jle",
                    str(output),
                ],
                output,
            ),
            (
                "conservative_scan",
                [
                    binary,
                    *common_flags,
                    *target_args,
                    "-tags",
                    "misconfig,exposure,headers,tech",
                    "-severity",
                    "info,low,medium,high,critical",
                    "-rl",
                    "50",
                    "-c",
                    "10",
                    "-timeout",
                    "10",
                    "-retries",
                    "1",
                    "-stats",
                    "-jle",
                    str(conservative_output),
                ],
                conservative_output,
            ),
            (
                "cve_scan",
                [
                    binary,
                    *common_flags,
                    *target_args,
                    *cve_selector_args,
                    "-severity",
                    "low,medium,high,critical",
                    "-rl",
                    "50",
                    "-c",
                    "10",
                    "-timeout",
                    "10",
                    "-retries",
                    "1",
                    "-stats",
                    "-jle",
                    str(cve_output),
                ],
                cve_output,
            ),
        ]

    def _parse_nuclei(self, ctx: ScanContext, export_path: Path, stdout: str) -> list[Finding]:
        findings, _parser_error = self._parse_nuclei_with_status(ctx, export_path, stdout)
        return findings

    def _parse_nuclei_with_status(
        self,
        ctx: ScanContext,
        export_path: Path,
        stdout: str,
    ) -> tuple[list[Finding], str]:
        items, parser_error = self._load_nuclei_records(export_path, stdout)
        unique_items: dict[tuple[str, ...], dict[str, Any]] = {}
        matched_locations: dict[tuple[str, ...], list[str]] = {}
        global_templates = {"django-debug-config-enabled"}
        for item in items:
            template_id = str(item.get("template-id") or "unknown")
            matcher_name = str(item.get("matcher-name") or "-")
            finding_type = str(item.get("type") or "-").lower()
            host = str(item.get("host") or ctx.target.display)
            matched_at = str(item.get("matched-at") or host or ctx.target.url)
            extracted_key = clean_text(item.get("extracted-results") or item.get("extracted_results") or [], 400)
            if template_id in global_templates:
                key = ("global", host.lower(), template_id.lower())
            elif finding_type == "ssl":
                key = ("ssl", host.lower(), template_id.lower(), matcher_name.lower(), extracted_key.lower())
            else:
                key = (
                    "endpoint",
                    template_id.lower(),
                    matched_at.lower(),
                    matcher_name.lower(),
                    extracted_key.lower(),
                )
            unique_items.setdefault(key, item)
            locations = matched_locations.setdefault(key, [])
            if matched_at and matched_at not in locations:
                locations.append(matched_at)

        findings = []
        for key, item in unique_items.items():
            info = item.get("info", {}) or {}
            severity = normalize_severity(info.get("severity", "Info"))
            extracted = item.get("extracted-results") or item.get("extracted_results") or []
            locations = matched_locations.get(key, [])
            evidence_parts = [
                f"Template={item.get('template-id', 'N/A')}",
                f"Matcher={item.get('matcher-name', '-')}",
                f"Type={item.get('type', '-')}",
                f"Host={item.get('host', '-')}",
            ]
            if extracted:
                evidence_parts.append(f"Extracted={clean_text(extracted, 400)}")
            if locations:
                evidence_parts.append(f"MatchedAt={locations[0]}")
            if len(locations) > 1:
                evidence_parts.append(f"AffectedLocations={clean_text(locations, 800)}")
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="External",
                    severity=severity,
                    title=f"Nuclei: {info.get('name') or item.get('template-id') or 'finding'}",
                    url=locations[0] if locations else item.get("host") or ctx.target.url,
                    endpoint=item.get("template-id", ""),
                    evidence=" | ".join(evidence_parts),
                    source=f"nuclei:{item.get('template-id', 'unknown')}",
                    confidence="medium",
                )
            )
        Console.ok(f"Nuclei parseado: {len(findings)} hallazgo(s)")
        return findings, parser_error

    def _load_nuclei_records(self, export_path: Path, stdout: str) -> tuple[list[dict[str, Any]], str]:
        items: list[dict[str, Any]] = []
        invalid_export_lines = 0
        if export_path.exists():
            raw = export_path.read_text(encoding="utf-8", errors="replace").strip()
            if raw:
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, list):
                        items.extend(item for item in parsed if isinstance(item, dict))
                    elif isinstance(parsed, dict):
                        nested = parsed.get("findings") or parsed.get("results")
                        if isinstance(nested, list):
                            items.extend(item for item in nested if isinstance(item, dict))
                        else:
                            items.append(parsed)
                except json.JSONDecodeError:
                    for line in raw.splitlines():
                        clean = line.strip()
                        if not clean:
                            continue
                        try:
                            parsed = json.loads(clean)
                        except json.JSONDecodeError:
                            invalid_export_lines += 1
                            continue
                        if isinstance(parsed, dict):
                            items.append(parsed)
                        elif isinstance(parsed, list):
                            items.extend(item for item in parsed if isinstance(item, dict))
        items.extend(self._parse_json_lines(stdout))
        parser_error = ""
        if invalid_export_lines:
            parser_error = (
                f"Error de parser Nuclei: {invalid_export_lines} linea(s) JSONL invalidas "
                f"en {export_path.name}."
            )
        return items, parser_error

    def _nuclei_empty_reason(
        self,
        returncode: int | None,
        timed_out: bool,
        stderr: str,
        stdout: str,
        export_path: Path,
        parsed_count: int,
        parser_error: str,
    ) -> str:
        if parsed_count:
            return ""
        text = f"{stdout}\n{stderr}".lower()
        if timed_out:
            return "Nuclei agoto el timeout antes de completar el perfil."
        host_abandoned_markers = (
            "found unresponsive permanently",
            "from target list as found unresponsive",
            "no address found for host",
            "could not resolve host",
            "dial tcp: lookup",
        )
        if any(marker in text for marker in host_abandoned_markers):
            return "Nuclei abandono el host por errores repetidos de resolucion o conectividad."
        template_error_markers = (
            "no templates provided",
            "no templates found",
            "no templates available",
            "could not load template",
            "failed to load template",
        )
        templates_loaded = self._extract_templates_loaded(text)
        if any(marker in text for marker in template_error_markers) or templates_loaded == 0:
            return "Nuclei no cargo plantillas utilizables para este perfil."
        if parser_error:
            return parser_error
        if returncode not in {0, None}:
            return f"Nuclei finalizo con codigo de salida no cero {returncode}."
        return "Nuclei completo correctamente: 0 hallazgos."

    def _parse_json_lines(self, text: str) -> list[dict[str, Any]]:
        out = []
        for line in text.splitlines():
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    out.append(parsed)
            except json.JSONDecodeError:
                continue
        return out

    def _slug(self, value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", value) or "target"

    @staticmethod
    def _registrable_domain(host: str) -> str:
        """Derive a practical base domain without adding a network PSL dependency."""
        value = str(host or "").strip().strip(".").lower()
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass
        labels = [label for label in value.split(".") if label]
        if len(labels) <= 2:
            return value
        common_second_level = {"ac", "co", "com", "edu", "gob", "gov", "mil", "net", "org"}
        if len(labels[-1]) == 2 and labels[-2] in common_second_level and len(labels) >= 3:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    @staticmethod
    def _origin_url(value: str) -> str:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme and parsed.netloc:
            return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
        return value.rstrip("/") + "/"


def build_target_classification_finding(target: Target) -> Finding:
    return Finding(
        target=target.display,
        category="Recon",
        severity="Info",
        title=f"Objetivo clasificado como {'IP' if target.is_ip else 'URL'}",
        url=target.url,
        evidence=f"Host={target.host} | IP={target.ip} | Puerto={target.port}",
        source="target_validation",
        confidence="high",
    )


class FindingScorer:
    IMPACT_REMEDIATION = {
        "CWE-89": (
            "Manipulacion de consultas SQL, extraccion o modificacion de datos, bypass de autenticacion y posible compromiso completo de la base de datos.",
            "Usar consultas parametrizadas/prepared statements, validacion server-side estricta y controles de menor privilegio en la cuenta de base de datos.",
        ),
        "CWE-79": (
            "Ejecucion de JavaScript en el navegador de la victima, robo de sesion, acciones en nombre del usuario y pivote hacia ataques client-side.",
            "Aplicar output encoding contextual, sanitizacion robusta, validacion server-side y Content-Security-Policy restrictiva.",
        ),
        "CWE-918": (
            "Abuso del servidor para consultar recursos internos, metadatos cloud, paneles privados o servicios no expuestos publicamente.",
            "Validar destinos, bloquear rangos internos/link-local, aplicar allowlists de egress y resolver DNS de forma segura antes de conectar.",
        ),
        "CWE-22": (
            "Lectura de archivos sensibles del servidor, exposicion de credenciales, configuracion interna o codigo fuente.",
            "Normalizar rutas, bloquear secuencias de traversal y servir archivos solo desde directorios permitidos mediante IDs controlados.",
        ),
        "CWE-78": (
            "Ejecucion de comandos del sistema con privilegios del proceso vulnerable, exfiltracion de datos y posible toma del servidor.",
            "Evitar shell execution con input de usuario, usar APIs seguras, allowlists estrictas y separacion de privilegios.",
        ),
        "CWE-90": (
            "Manipulacion de filtros LDAP, enumeracion de usuarios, bypass de autenticacion o acceso no autorizado a directorios corporativos.",
            "Escapar filtros LDAP, usar consultas parametrizadas y validar atributos permitidos.",
        ),
        "CWE-1336": (
            "Ejecucion de expresiones o codigo en el motor de plantillas, lectura de variables internas y posible RCE segun el engine.",
            "No renderizar input de usuario como plantilla, usar sandboxing, allowlists de plantillas y separar datos de logica de render.",
        ),
        "CWE-287": (
            "Bypass de autenticacion, emision de sesion/token a usuarios no autorizados y acceso directo a funcionalidades protegidas.",
            "Reforzar autenticacion server-side, bloquear payloads de bypass, validar flujos de login y revisar controles de sesion.",
        ),
        "CWE-639": (
            "Acceso horizontal o vertical a objetos de otros usuarios, fuga de datos sensibles y acciones no autorizadas.",
            "Validar autorizacion objeto por objeto en backend, no confiar en IDs del cliente y aplicar controles por rol/propietario.",
        ),
        "CWE-862": (
            "Recursos sensibles pueden servirse sin una comprobacion de autorizacion adecuada.",
            "Exigir autenticacion y autorizacion centralizada antes de servir recursos protegidos.",
        ),
        "CWE-942": (
            "Lectura de respuestas desde origenes no confiables, posible exposicion de datos si existen cookies o tokens accesibles.",
            "Restringir Access-Control-Allow-Origin a dominios confiables y evitar credenciales con origenes dinamicos o wildcard.",
        ),
        "CWE-347": (
            "Tokens manipulables, sesiones persistentes o claims sensibles expuestos pueden facilitar suplantacion o escalamiento.",
            "Validar firma, algoritmo, expiracion y claims; evitar datos sensibles dentro del JWT.",
        ),
        "CWE-326": (
            "Debilitamiento del canal cifrado, downgrade TLS, exposicion a MITM o perdida de garantias de transporte seguro.",
            "Habilitar TLS moderno, certificados validos, HSTS y cifrados fuertes; retirar protocolos obsoletos.",
        ),
        "CWE-693": (
            "Defensas del navegador debilitadas frente a XSS, clickjacking, MIME sniffing, cacheo indebido o fuga de informacion.",
            "Aplicar cabeceras de seguridad consistentes: HSTS, CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options y Cache-Control.",
        ),
        "CWE-200": (
            "Exposicion de metadatos, rutas internas, versiones, documentacion tecnica o informacion util para ampliar superficie de ataque.",
            "Restringir documentacion y archivos auxiliares en produccion, sanitizar metadatos y limitar acceso por autenticacion.",
        ),
        "CWE-346": (
            "Metadatos de confianza inconsistentes pueden romper integraciones SSO, causar redirecciones incorrectas o facilitar confusion entre entidades.",
            "Publicar metadata SAML alineada con el host, esquema y puerto reales; validar entityID, ACS, SLO y certificados contra el entorno desplegado.",
        ),
        "CWE-548": (
            "Listados de directorio exponen estructura interna, librerias, archivos auxiliares y rutas que aceleran enumeracion y ataques posteriores.",
            "Deshabilitar autoindex/Options Indexes, bloquear listados de directorio y publicar solo artefactos estaticos necesarios.",
        ),
        "CWE-1035": (
            "Versiones o componentes con CVEs conocidos pueden permitir explotacion directa segun servicio, version y exposicion.",
            "Validar version afectada, aplicar parches del proveedor, mitigar exposicion y documentar excepciones con controles compensatorios.",
        ),
    }

    RULES = [
        (
            ("directory listing", "autoindex"),
            "CWE-548",
            "A02:2025 - Configuración de seguridad incorrecta",
            "5.3",
            "Disable directory listing and expose only required static assets.",
        ),
        (
            ("saml metadata", "entityid", "acs"),
            "CWE-346",
            "A02:2025 - Configuración de seguridad incorrecta",
            "6.5",
            "Align SAML metadata entityID, ACS and SLO URLs with the deployed host, scheme and port.",
        ),
        (
            ("ffuf discovered sensitive-looking", "sensitive-looking unauthenticated routes"),
            "CWE-200",
            "A01:2025 - Falla de control de acceso",
            "5.3",
            "Review exposed routes, require authentication where needed and remove debug/admin/static listings.",
        ),
        (
            ("sqli", "sql injection"),
            "CWE-89",
            "A05:2025 - Inyección",
            "9.1",
            "Use parameterized queries and server-side input validation.",
        ),
        (
            ("x-xss-protection", "x-content-type-options", "x-frame-options", "security headers", "missing security headers"),
            "CWE-693",
            "A02:2025 - Configuración de seguridad incorrecta",
            "5.3",
            "Deploy browser security headers consistently across all responses.",
        ),
        (
            ("xss", "cross-site", "dom xss"),
            "CWE-79",
            "A05:2025 - Inyección",
            "8.0",
            "Apply contextual output encoding and enforce a restrictive CSP.",
        ),
        (
            ("ssrf",),
            "CWE-918",
            "A01:2025 - Falla de control de acceso",
            "9.0",
            "Validate outbound URLs, block internal ranges, and use egress allowlists.",
        ),
        (
            ("lfi", "traversal", "path traversal"),
            "CWE-22",
            "A01:2025 - Falla de control de acceso",
            "8.6",
            "Normalize paths and restrict file access to approved directories.",
        ),
        (
            ("command injection",),
            "CWE-78",
            "A05:2025 - Inyección",
            "9.8",
            "Avoid shell execution with user input and use strict command allowlists.",
        ),
        (
            ("ldap injection",),
            "CWE-90",
            "A05:2025 - Inyección",
            "8.1",
            "Escape LDAP filters and use parameterized directory queries.",
        ),
        (
            ("ssti", "template injection"),
            "CWE-1336",
            "A05:2025 - Inyección",
            "9.0",
            "Avoid rendering user input as templates and sandbox template engines.",
        ),
        (
            ("auth", "login bypass", "authentication"),
            "CWE-287",
            "A07:2025 - Fallos de autenticación",
            "9.0",
            "Enforce server-side authentication checks and harden login workflows.",
        ),
        (
            ("authorization", "idor", "bola"),
            "CWE-639",
            "A01:2025 - Falla de control de acceso",
            "8.8",
            "Perform object-level authorization checks for every sensitive request.",
        ),
        (
            ("cors",),
            "CWE-942",
            "A02:2025 - Configuración de seguridad incorrecta",
            "7.4",
            "Restrict CORS origins and never allow credentials with wildcard origins.",
        ),
        (
            ("jwt",),
            "CWE-347",
            "A08:2025 - Fallos de integridad de software o datos",
            "7.5",
            "Use strong JWT algorithms, verify signatures, and enforce exp/iat claims.",
        ),
        (
            ("tls", "ssl", "certificate"),
            "CWE-326",
            "A04:2025 - Fallos criptográficos",
            "6.5",
            "Use modern TLS, valid certificates, HSTS, and strong cipher suites.",
        ),
        (
            ("headers", "csp", "clickjacking"),
            "CWE-693",
            "A02:2025 - Configuración de seguridad incorrecta",
            "5.3",
            "Deploy security headers consistently across all responses.",
        ),
        (
            ("openapi", "swagger", "source map", "information disclosure"),
            "CWE-200",
            "A02:2025 - Configuración de seguridad incorrecta",
            "4.3",
            "Restrict exposed metadata and remove sensitive operational details.",
        ),
        (
            ("nmap", "cve", "nuclei"),
            "CWE-1035",
            "A03:2025 - Fallos en la cadena de suministro de software",
            "7.5",
            "Validate affected software versions and apply vendor remediation.",
        ),
    ]

    def __init__(self, knowledge_base: KnowledgeBase | None = None) -> None:
        self.knowledge_base = knowledge_base

    def apply(self, findings: list[Finding]) -> None:
        for finding in findings:
            self._apply_one(finding)

    def _apply_one(self, finding: Finding) -> None:
        haystack = " ".join([finding.category, finding.title, finding.source, finding.evidence]).lower()
        for needles, cwe, owasp, cvss, recommendation in self.RULES:
            if any(needle in haystack for needle in needles):
                finding.cwe = finding.cwe or cwe
                finding.owasp = finding.owasp or owasp
                finding.cvss = finding.cvss or self._severity_cvss(finding.severity, cvss)
                finding.recommendation = finding.recommendation or recommendation
                break
        if self.knowledge_base:
            self.knowledge_base.apply(finding)
        if finding.cwe in self.IMPACT_REMEDIATION:
            impact, remediation = self.IMPACT_REMEDIATION[finding.cwe]
            finding.impact = finding.impact or impact
            finding.remediation = finding.remediation or remediation
        if finding.cvss and self._cvss_label(finding.cvss) != finding.severity:
            finding.cvss = self._severity_cvss(finding.severity, "")
        finding.evidence_strength = finding.evidence_strength or self._evidence_strength(finding)
        finding.false_positive_risk = finding.false_positive_risk or self._false_positive_risk(finding)
        if not finding.cvss:
            finding.cvss = self._severity_cvss(finding.severity, "")
        if not finding.recommendation and finding.severity != "Info":
            finding.recommendation = "Validar la condicion manualmente, capturar evidencia de soporte y corregir el control afectado."
        finding.remediation = finding.remediation or finding.recommendation
        if finding.owasp or finding.cwe or finding.severity != "Info":
            finding.owasp = normalize_owasp_2025(
                finding.owasp,
                cwe=finding.cwe,
                category=finding.category,
                title=finding.title,
                source=finding.source,
                evidence=finding.evidence,
                details=finding.details,
            )
        self._localize_finding(finding)

    def _localize_finding(self, finding: Finding) -> None:
        finding.title = translate_visible_text(finding.title)
        finding.evidence = translate_visible_text(finding.evidence)
        finding.impact = translate_visible_text(finding.impact)
        finding.remediation = translate_visible_text(finding.remediation)
        finding.recommendation = translate_visible_text(finding.recommendation)
        finding.details = translate_visible_text(finding.details)
        finding.cvss = translate_visible_text(finding.cvss)

    def _severity_cvss(self, severity: str, suggested: str) -> str:
        if suggested:
            suggested_label = self._cvss_label(suggested)
            if suggested_label == severity:
                return f"{suggested} ({suggested_label})"
        score = {
            "Critical": "9.0",
            "High": "7.5",
            "Medium": "5.3",
            "Low": "3.1",
            "Info": "0.0",
        }.get(severity, "0.0")
        return f"{score} ({self._cvss_label(score)})"

    def _cvss_label(self, value: str) -> str:
        try:
            score = float(str(value).split()[0])
        except Exception:
            return "Info"
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score > 0:
            return "Low"
        return "Info"

    def _evidence_strength(self, finding: Finding) -> str:
        if finding.confidence == "high" and any([finding.payload, finding.status, finding.evidence]):
            return "strong"
        if finding.confidence in {"high", "medium"}:
            return "moderate"
        return "weak"

    def _false_positive_risk(self, finding: Finding) -> str:
        if finding.confidence == "high" and finding.evidence_strength == "strong":
            return "low"
        if finding.confidence == "low" or finding.severity == "Info":
            return "high"
        return "medium"


class ScanTitan:
    MODULE_HEARTBEAT_SECONDS = 15.0

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self.telemetry = RuntimeTelemetry(RUNTIME_FILE)
        self.config.telemetry = self.telemetry
        self.config.runtime_control.telemetry = self.telemetry
        self.telemetry.phase("initializing", "Runtime Scan Titan inicializado")
        self.state = StateStore(STATE_FILE)
        self.reporter = ReportWriter(REPORTS_DIR, HISTORY_DIR)
        self.recon_matrix = ReconMatrixManager(RECON_FILE)
        self.sitemap = ReconSiteMapManager(REPORTS_DIR, SCAN_VERSION)
        self.external = ExternalTools(config)
        self.evidence = EvidenceManager(
            REPORTS_DIR,
            enable_cards=config.policy.evidence_cards,
            enable_console_screenshots=config.policy.console_screenshots,
            enable_browser_evidence=config.policy.browser_evidence,
            browser_timeout_seconds=config.policy.browser_timeout_seconds,
            browser_max_per_target=config.policy.browser_evidence_max_per_target,
        )
        self.technical_detail = TechnicalDetailExporter(config.technical_detail)
        self._emitted_occurrences: set[str] = set()
        self.knowledge_base = (
            KnowledgeBase.load(config.knowledge_path, config.knowledge_min_score)
            if config.knowledge_enabled
            else KnowledgeBase(config.knowledge_path, [], config.knowledge_min_score)
        )
        if config.knowledge_enabled and self.knowledge_base.entries:
            Console.ok(f"Base de conocimiento cargada: {len(self.knowledge_base.entries)} entradas")
        elif config.knowledge_enabled:
            Console.warn(f"Base de conocimiento no encontrada o vacia: {config.knowledge_path}")
        self.scorer = FindingScorer(self.knowledge_base if config.knowledge_enabled else None)
        self.wordlists = WordlistLoader(WORDLISTS_DIR, config.max_wordlist_entries).load()

    async def run(self) -> int:
        control_task = asyncio.create_task(self.config.runtime_control.keyboard_loop())
        try:
            self.telemetry.phase("cleanup", "limpieza de targets")
            CleanupManager(self.config.targets_dir).run()
            targets = TargetLoader(self.config).load()
            if not targets:
                Console.error(f"No se encontraron objetivos. Agregue targets en {self.config.targets_file}.")
                self.telemetry.start([], self.config)
                self.telemetry.finish("no_targets")
                return 2
            audit_id = self.config.ensure_audit_id()
            self.telemetry.start(targets, self.config)
            Console.ok(f"Targets loaded: {len(targets)}")
            if audit_id:
                label = "ID maestro automatico de auditoria" if self.config.audit_id_automatic else "ID maestro de auditoria"
                Console.ok(f"{label}: {audit_id}")
            Console.ok(
                "Modo de red estable: TCPConnector=25 | semaforo HTTP<=20 | "
                f"targets={self.config.target_concurrency} | general={self.config.jitter_min_seconds:.1f}-"
                f"{self.config.jitter_max_seconds:.1f}s/{self.config.throttle_batch_size} peticiones | "
                f"payload={self.config.payload_jitter_min_seconds:.1f}-"
                f"{self.config.payload_jitter_max_seconds:.1f}s/{self.config.payload_throttle_batch_size} peticion"
            )
            Console.ok(
                "Perfil de politica: "
                f"{self.config.policy.profile} | browser={self.config.policy.enable_browser} | "
                f"pruebas-con-cambio={self.config.policy.allow_state_changing_api_tests} | "
                f"tarjetas-evidencia={self.config.policy.evidence_cards} | "
                f"evidencia-browser={self.config.policy.browser_evidence}"
            )
            if self.config.full_power:
                Console.warn(
                    "MODO FULL POWER: todos los modulos/perfiles externos habilitados | "
                    f"max-tests={self.config.max_tests_per_module} | wordlists=sin-limite | "
                    f"ZAP={self.config.zap_mode} | report-min={self.config.report_min_severity}"
                )
            Console.ok(
                "ZAP externo: "
                f"enabled={self.config.policy.enable_zap} | mode={self.config.zap_mode} | "
                f"api={self.config.zap_api_url}"
            )
            self.telemetry.phase("tool_inventory", "inventario de herramientas externas")
            self.external.write_tool_inventory()
            target_semaphore = asyncio.Semaphore(self.config.target_concurrency)
            http_semaphore = asyncio.Semaphore(self.config.concurrency)
            self.telemetry.phase("scan", "pipeline de objetivos")
            results = await asyncio.gather(
                *(self._scan_target_guarded(target, target_semaphore, http_semaphore) for target in targets)
            )
            valid_results = [item for item in results if item]
            if valid_results:
                self.reporter.write_history(valid_results, now_text())
                self.write_master_technical_detail(valid_results)
                formal_report = self.reporter.write_formal_report(valid_results, now_text())
                Console.ok(f"Reporte formal generado: {formal_report}")
            self.state.save()
            self.telemetry.set_counts_from_records(self.state.active_records())
            self.print_dashboard()
            try:
                recon_dashboard = self.recon_matrix.write_dashboard(REPORTS_DIR / "Recon_Dashboard.html")
                Console.ok(f"Dashboard de recon actualizado: {recon_dashboard}")
            except Exception as exc:
                Console.warn(f"No se pudo generar el dashboard de recon: {clean_text(exc, 240)}")
            try:
                sitemap_dashboard = self.sitemap.write_html()
                Console.ok(f"Site Map de recon actualizado: {sitemap_dashboard}")
            except Exception as exc:
                Console.warn(f"No se pudo generar el Site Map de recon: {clean_text(exc, 240)}")
            self.telemetry.phase("dashboard", "generacion de dashboard HTML")
            await self.generate_html_dashboard()
            self.telemetry.finish("finished")
            return 0
        except KeyboardInterrupt:
            self.telemetry.finish("interrupted")
            raise
        except asyncio.CancelledError:
            self.telemetry.finish("cancelled")
            raise
        except Exception as exc:
            self.telemetry.state["last_error"] = clean_text(exc, 600)
            self.telemetry.finish("failed")
            raise
        finally:
            self.config.runtime_control.stop_listener()
            control_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await control_task

    async def _scan_target_guarded(
        self,
        target: Target,
        target_semaphore: asyncio.Semaphore,
        http_semaphore: asyncio.Semaphore,
    ) -> dict[str, Any] | None:
        async with target_semaphore:
            try:
                await self.config.runtime_control.wait_if_paused()
                if self.config.runtime_control.finish_requested:
                    Console.warn(f"Objetivo omitido por solicitud de finalizacion controlada: {target.display}")
                    return None
                return await self.scan_target(target, http_semaphore)
            except Exception as exc:
                Console.error(f"Objetivo fallido {target.display}: {exc}")
                self.telemetry.target_failed(target, exc)
                return None

    async def scan_target(self, target: Target, http_semaphore: asyncio.Semaphore) -> dict[str, Any]:
        Console.phase(f"TARGET: {target.url} ({target.ip})")
        self.telemetry.target_start(target)
        started = time.monotonic()
        limits = ScanLimits(
            timeout=self.config.timeout,
            max_tests_per_module=self.config.max_tests_per_module,
            delay_seconds=self.config.delay_seconds,
            jitter_min_seconds=self.config.jitter_min_seconds,
            jitter_max_seconds=self.config.jitter_max_seconds,
            throttle_batch_size=self.config.throttle_batch_size,
            adaptive_waf_block_threshold=self.config.adaptive_waf_block_threshold,
            adaptive_plateau_threshold=self.config.adaptive_plateau_threshold,
            allow_cloud_ssrf=self.config.allow_cloud_ssrf,
            allow_state_changing_api_tests=self.config.policy.allow_state_changing_api_tests,
            perform_upload_attempts=self.config.policy.perform_upload_attempts,
            allow_bruteforce=self.config.policy.allow_bruteforce,
            allow_rate_limit_probes=self.config.policy.allow_rate_limit_probes,
            rate_limit_probe_requests=self.config.policy.rate_limit_probe_requests,
            policy=self.config.policy,
            runtime_control=self.config.runtime_control,
        )
        connector = aiohttp.TCPConnector(limit=25, limit_per_host=20, ttl_dns_cache=300)
        async with aiohttp.ClientSession(
            connector=connector,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0 Safari/537.36 ScanTitan/18"
                ),
                "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
            },
            trust_env=True,
        ) as session:
            http = AsyncHttpClient(
                session=session,
                semaphore=http_semaphore,
                limits=limits,
                verify_tls=self.config.verify_tls,
            )
            recon: dict[str, Any] = {
                "target": target.display,
                "url": target.url,
                "ip": target.ip,
                "host_type": "IP" if target.is_ip else "URL",
                "technologies": [],
                "open_ports": [],
                "services": [],
                "ports_services": [],
                "discovered_paths": [],
                "login_forms": [],
                "js_libraries": [],
                "headers_exposed": [],
                "cookies_status": "",
                "endpoints": [],
                "exposed_files": [],
                "subdomains": [],
                "websockets": [],
                "site_map": [],
                "site_functions": [],
                "forms": [],
                "http_methods": [],
                "waf_cdn": [],
                "tls_supported_protocols": [],
                "nmap_scripts": [],
                "zap_alerts": [],
                "wordlist_path_hits": [],
                "unauthenticated_routes": [],
                "directory_listings": [],
                "static_residue_files": [],
                "saml_metadata": {},
                "whatweb_technologies": [],
                "whatweb_frameworks": [],
                "whatweb_servers": [],
                "whatweb_categories": [],
                "whatweb_status": "",
                "whatweb_evidence": "",
                "wafw00f_status": "",
                "wafw00f_vendor": "",
                "wafw00f_evidence": "",
                "waf_resilience_summary": "",
                "waf_probe_results": [],
            }
            ctx = ScanContext(
                target=target,
                http=http,
                wordlists=self.wordlists,
                limits=limits,
                recon=recon,
                heartbeat=lambda module, detail, tested, found: self._heartbeat(
                    module,
                    detail,
                    tested,
                    found,
                ),
                policy=self.config.policy,
            )
            findings: list[Finding] = []
            if self.config.include_recon_info_findings:
                findings.append(build_target_classification_finding(target))
            for module_cls in DEFAULT_MODULES:
                await self.config.runtime_control.wait_if_paused()
                if self.config.runtime_control.finish_requested:
                    Console.warn(f"Finalizacion ordenada antes del siguiente modulo en {target.display}")
                    break
                module = module_cls()
                if not self.config.policy.module_enabled(module.name):
                    Console.warn(f"MODULE SKIPPED BY POLICY: {module.name}")
                    continue
                try:
                    ctx.limits.max_tests_per_module = self.config.module_test_budget(module.name)
                    findings.extend(await self._run_module(module, ctx, self.config.module_timeout_for(module.name)))
                except Exception as exc:
                    Console.warn(f"Componente del pipeline fallido: {module_cls.__name__}: {exc}")
                await asyncio.sleep(2.0)
            if self.config.runtime_control.finish_requested:
                Console.warn(f"Herramientas externas omitidas por finalizacion ordenada en {target.display}")
            else:
                await self.config.runtime_control.wait_if_paused()
                external_findings = await self.external.run(ctx)
                self._emit_new_findings(external_findings)
                findings.extend(external_findings)

        timestamp = now_text()
        reportable_findings = correlate_findings(
            self._reportable_findings(findings),
            asset=target.ip or target.display,
        )
        self.scorer.apply(reportable_findings)
        enriched = self.state.enrich(reportable_findings, target.display, timestamp)
        await asyncio.to_thread(
            self.evidence.attach_artifacts,
            enriched,
            timestamp,
            capture_browser=self.config.policy.browser_evidence,
        )
        self.state.sync_artifacts(enriched)
        report_path = self.reporter.write_target_report(target, enriched, timestamp)
        recon_hits = recon.get("wordlist_path_hits", [])
        Console.step(
            f"Actualizacion compacta de Recon Matrix iniciada: objetivo={target.display} rutas_raw={len(recon_hits)}"
        )
        self.telemetry.phase("recon_matrix", f"Compact update for {target.display}")
        recon_task = asyncio.create_task(
            asyncio.to_thread(
                self.recon_matrix.update_target_bundle,
                self._recon_row(target, recon, timestamp),
                target.display,
                recon_hits,
                timestamp,
            )
        )
        while not recon_task.done():
            done, _pending = await asyncio.wait({recon_task}, timeout=5.0)
            if recon_task in done:
                break
            Console.heartbeat("recon_matrix", "compacting and saving", 0, 0)
            self.telemetry.heartbeat("recon_matrix", "compacting and saving", 0, 0)
        recon_stats = await recon_task
        Console.ok(
            "Recon Matrix updated once: "
            f"kept={recon_stats['kept']} discarded/duplicate={recon_stats['discarded']}"
        )
        try:
            sitemap_stats = await asyncio.to_thread(
                self.sitemap.update_target,
                target=target.display,
                base_url=target.url,
                ip=target.ip,
                recon=recon,
                timestamp=timestamp,
            )
            Console.ok(
                "Site Map de recon actualizado: "
                f"rutas={sitemap_stats['routes']} externas={sitemap_stats['external']} "
                f"html={sitemap_stats['html']}"
            )
        except Exception as exc:
            Console.warn(f"No se pudo actualizar el Site Map de recon: {clean_text(exc, 240)}")
        duration = time.monotonic() - started
        self.print_target_summary(target, enriched, duration, report_path)
        self.telemetry.target_end(target, enriched, duration)
        return {
            "target": target,
            "findings": enriched,
            "duration": duration,
            "report": report_path,
            "timestamp": timestamp,
        }

    def _reportable_findings(self, findings: list[Finding]) -> list[Finding]:
        min_rank = SEVERITY_ORDER.get(self.config.report_min_severity, SEVERITY_ORDER["Low"])
        reportable: list[Finding] = []
        for finding in findings:
            severity = normalize_severity(finding.severity)
            if SEVERITY_ORDER.get(severity, 99) > min_rank:
                continue
            category = str(finding.category or "").lower()
            source = str(finding.source or "").lower()
            title = str(finding.title or "").lower()
            if category == "pipeline" and not self.config.include_pipeline_findings:
                continue
            if severity == "Info" and not self.config.include_recon_info_findings:
                continue
            if category.startswith("recon") or category in {
                "external/ffuf",
                "external/whatweb",
                "external/subfinder",
                "external/wappy",
                "external/wafw00f",
            }:
                continue
            if source == "target_validation" or source.startswith(("whatweb", "subfinder", "ffuf", "wappy", "wafw00f")):
                continue
            if "classified as" in title or title.startswith("functional site map"):
                continue
            if finding_quality_exclusion(finding):
                continue
            if str(finding.confidence or "").lower() == "low":
                continue
            if str(finding.false_positive_risk or "").lower() == "high":
                continue
            finding.severity = severity
            reportable.append(finding)
        return reportable

    def write_master_technical_detail(self, results: list[dict[str, Any]]) -> Path | None:
        if not self.config.technical_detail.enabled:
            return None
        Console.step(
            f"Actualizando un Detalle Tecnico historico para la auditoria {self.config.technical_detail.audit_id} "
            f"con {len(results)} objetivo(s) analizados"
        )
        try:
            output_path = self.technical_detail.export_results(results)
        except Exception as exc:
            Console.warn(f"Detalle tecnico maestro omitido: {clean_text(exc, 240)}")
            return None
        if output_path:
            Console.ok(f"Detalle tecnico maestro actualizado una vez para esta ejecucion: {output_path}")
        else:
            Console.warn("Detalle tecnico maestro omitido: no hay hallazgos elegibles o la plantilla no esta disponible")
        return output_path

    def _heartbeat(self, module: str, detail: str, tested: int, found: int) -> None:
        Console.heartbeat(module, detail, tested, found)
        self.telemetry.heartbeat(module, detail, tested, found)

    async def _module_pulse(self, module: str, ctx: ScanContext) -> None:
        started = time.monotonic()
        initial_completed = ctx.http.requests_completed
        while True:
            await asyncio.sleep(self.MODULE_HEARTBEAT_SECONDS)
            now = time.monotonic()
            active = ctx.http.requests_active
            stats = {
                "completed": ctx.http.requests_completed - initial_completed,
                "active": active,
                "waiting": max(0, ctx.http.requests_waiting - active),
                "seconds_without_response": round(now - max(started, ctx.http.last_completed_at), 1),
            }
            status = "en pausa" if self.config.runtime_control.is_paused else "en curso"
            detail = (
                f"{status} | {now - started:.0f}s | HTTP terminadas={stats['completed']} "
                f"activas={active} en espera={stats['waiting']} | "
                f"ultima respuesta hace {stats['seconds_without_response']:.0f}s"
            )
            Console.step(f"{module}: {detail}")
            self.telemetry.module_activity(module, detail, stats)

    async def _run_module(self, module: Any, ctx: ScanContext, timeout: int) -> list[Finding]:
        Console.phase(f"MODULE: {module.name}")
        throttle = self.config.apply_module_throttle(module.name, ctx.limits)
        timeout_label = "sin limite" if int(timeout or 0) <= 0 else f"{timeout}s"
        Console.step(
            f"Controles del modulo: pruebas<={ctx.limits.max_tests_per_module} "
            f"timeout={timeout_label} ritmo={throttle['mode']} "
            f"jitter={throttle['jitter_min']}-{throttle['jitter_max']}s/"
            f"{throttle['batch_size']} peticion(es)"
        )
        self.telemetry.module_start(ctx.target, module.name, ctx.limits.max_tests_per_module, timeout)
        started = time.monotonic()
        pulse_task = asyncio.create_task(self._module_pulse(module.name, ctx))
        try:
            await self.config.runtime_control.wait_if_paused()
            if self.config.runtime_control.finish_requested:
                self.telemetry.module_end(module.name, [], "skipped", "Finalizacion controlada solicitada")
                return []
            if int(timeout or 0) <= 0:
                findings = await module.run(ctx)
            else:
                findings = await asyncio.wait_for(module.run(ctx), timeout=timeout)
            self._emit_new_findings(findings)
            status = "skipped" if self.config.runtime_control.finish_requested else "finished"
            self.telemetry.module_end(module.name, findings, status)
            Console.ok(f"{module.name}: {len(findings)} hallazgo(s) en {time.monotonic() - started:.1f}s")
            return findings
        except asyncio.TimeoutError:
            Console.warn(f"{module.name}: timeout del modulo despues de {timeout}s")
            if not self.config.include_pipeline_findings:
                self.telemetry.module_end(module.name, [], "timeout", f"Timeout despues de {timeout}s")
                return []
            timeout_findings = [
                Finding(
                    target=ctx.target.display,
                    category="Pipeline",
                    severity="Info",
                    title=f"Timeout del modulo: {module.name}",
                    url=ctx.target.url,
                    evidence=f"Timeout despues de {timeout}s",
                    source=module.name,
                    confidence="high",
                )
            ]
            self.telemetry.module_end(module.name, timeout_findings, "timeout", f"Timeout despues de {timeout}s")
            return timeout_findings
        except Exception as exc:
            Console.warn(f"{module.name}: {exc}")
            failed_findings = [
                Finding(
                    target=ctx.target.display,
                    category="Pipeline",
                    severity="Info",
                    title=f"Modulo fallido: {module.name}",
                    url=ctx.target.url,
                    evidence=str(exc),
                    source=module.name,
                    confidence="high",
                )
            ]
            self.telemetry.module_end(module.name, failed_findings, "failed", str(exc))
            return failed_findings
        finally:
            pulse_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await pulse_task

    def _emit_new_findings(self, findings: list[Finding]) -> None:
        display_findings = correlate_findings(self._reportable_findings(findings))
        display_findings = [
            finding
            for finding in display_findings
            if finding.fingerprint not in self._emitted_occurrences
        ]
        if not display_findings:
            return
        timestamp = now_text()
        self.scorer.apply(display_findings)
        self.evidence.attach_artifacts(display_findings, timestamp)
        for finding in display_findings:
            Console.finding(finding)
            self._emitted_occurrences.add(finding.fingerprint)
        self.telemetry.add_findings(display_findings)
        self.telemetry.write()

    def _recon_row(self, target: Target, recon: dict[str, Any], timestamp: str) -> dict[str, Any]:
        endpoints = [
            item.get("url", "")
            for item in recon.get("endpoints", [])
            if isinstance(item, dict) and item.get("url")
        ]
        site_map = recon.get("site_map", [])[:300]
        site_functions = recon.get("site_functions", [])
        ports_services = recon.get("ports_services") or recon.get("open_ports", [])
        services = recon.get("services", [])
        headers = recon.get("headers_exposed") or recon.get("security_headers", "")
        if recon.get("nmap_scripts"):
            services = list(services) + [f"Nmap Scripts: {clean_text(recon.get('nmap_scripts'), 1500)}"]
        if recon.get("waf_cdn"):
            services = list(services) + [f"WAF/CDN: {clean_text(recon.get('waf_cdn'), 500)}"]
        if recon.get("wafw00f_evidence"):
            services = list(services) + [f"wafw00f: {clean_text(recon.get('wafw00f_evidence'), 700)}"]
        if recon.get("waf_resilience_summary"):
            services = list(services) + [f"Perfil WAF: {clean_text(recon.get('waf_resilience_summary'), 700)}"]
        if recon.get("adaptive_stops"):
            services = list(services) + [f"Cortes adaptativos: {clean_text(recon.get('adaptive_stops'), 1200)}"]
        if recon.get("http_methods"):
            services = list(services) + [f"HTTP Methods: {', '.join(recon.get('http_methods', []))}"]
        if recon.get("tls_supported_protocols"):
            services = list(services) + [f"TLS Protocols: {', '.join(recon.get('tls_supported_protocols', []))}"]
        if recon.get("zap_alerts"):
            services = list(services) + [f"ZAP Alerts: {clean_text(recon.get('zap_alerts'), 1800)}"]
        if site_functions:
            endpoints.append(f"Functional Map: {', '.join(site_functions)}")
        return {
            "Target": target.display,
            "IP": target.ip,
            "Tipo": recon.get("host_type"),
            "URL Base": recon.get("url") or target.url,
            "Puertos Expuestos": ports_services,
            "Servicios": services,
            "Tecnologias": recon.get("technologies", []),
            "Enrutamiento/Endpoints descubiertos": list(
                dict.fromkeys(endpoints + site_map + recon.get("discovered_paths", []))
            ),
            "Formularios de Login": list(dict.fromkeys(recon.get("login_forms", []) + recon.get("forms", []))),
            "Librerias JS": recon.get("js_libraries", []),
            "Estado de Cookies": recon.get("cookies_status", ""),
            "Headers Expuestos": headers,
            "WAF/CDN": recon.get("waf_cdn", []),
            "WAF wafw00f": recon.get("wafw00f_evidence", ""),
            "Perfil WAF": recon.get("waf_resilience_summary", ""),
            "Pruebas WAF": [
                (
                    f"{item.get('categoria', '')}:{item.get('tecnica', '')} "
                    f"estado={item.get('status', '')} veredicto={item.get('veredicto', '')}"
                )
                for item in recon.get("waf_probe_results", [])
                if isinstance(item, dict)
            ][:120],
            "Cortes Adaptativos": [
                (
                    f"{item.get('module', '')}: "
                    f"{item.get('stop_reason') or (str(item.get('stopped_inputs', 0)) + ' entrada(s) sin variacion')}"
                )
                for item in recon.get("adaptive_stops", [])
                if isinstance(item, dict)
            ],
            "Archivos Expuestos": recon.get("exposed_files", []),
            "Subdominios": recon.get("subdomains", []),
            "WebSockets": recon.get("websockets", []),
            "API Specs": recon.get("api_specs", []),
            "GraphQL": recon.get("graphql_endpoints", []),
            "Browser Routes": recon.get("browser_routes", []) or recon.get("browser_login_routes", []),
            "Browser Storage": recon.get("browser_storage_keys", ""),
            "Browser Screenshots": recon.get("browser_screenshots", []),
            "Sitemap Sin Autenticacion": recon.get("unauthenticated_routes", []),
            "Directory Listings": recon.get("directory_listings", []),
            "SAML Metadata": recon.get("saml_metadata", {}),
            "Residuos Staticos": recon.get("static_residue_files", []),
            "Pruebas Diferidas Por Politica": recon.get("policy_deferred_tests", []),
            "Ultima Ejecucion": timestamp,
            "WhatWeb Tecnologias": [
                self.external._whatweb_label(item)
                for item in recon.get("whatweb_technologies", [])
                if isinstance(item, dict)
            ],
            "WhatWeb Frameworks": recon.get("whatweb_frameworks", []),
            "WhatWeb Servidores": recon.get("whatweb_servers", []),
            "WhatWeb Categorias": recon.get("whatweb_categories", []),
            "WhatWeb Estado": recon.get("whatweb_status", ""),
            "WhatWeb Evidencia": recon.get("whatweb_evidence", ""),
        }

    def print_target_summary(self, target: Target, findings: list[Finding], duration: float, report_path: Path) -> None:
        counts = Counter(finding.severity for finding in findings)
        print(f"\n{Fore.WHITE}Resumen del objetivo: {target.display}")
        for severity in ("Critical", "High", "Medium", "Low", "Info"):
            print(f"  {severity_label_es(severity):<10}: {counts.get(severity, 0)}")
        print(f"  Total     : {len(findings)}")
        print(f"  Duracion  : {duration:.1f}s")
        print(f"  Reporte   : {report_path}{Style.RESET_ALL}")

    def print_dashboard(self) -> None:
        min_rank = SEVERITY_ORDER.get(self.config.report_min_severity, SEVERITY_ORDER["Low"])
        records = [
            record
            for record in self.state.active_records()
            if SEVERITY_ORDER.get(normalize_severity(record.get("severity", "Info")), 99) <= min_rank
        ]
        print(f"\n{Fore.MAGENTA}{HEADER_SEPARATOR}")
        print(f"{Fore.MAGENTA}  DASHBOARD GENERAL - VULNERABILIDADES VIGENTES")
        print(f"{Fore.MAGENTA}{HEADER_SEPARATOR}{Style.RESET_ALL}")
        if not records:
            Console.ok("No hay vulnerabilidades activas en el estado local.")
            return
        counts = Counter(normalize_severity(record.get("severity", "Info")) for record in records)
        for severity in ("Critical", "High", "Medium", "Low", "Info"):
            print(f"  {severity_label_es(severity):<10}: {counts.get(severity, 0)}")
        header = (
            f"{'SEV':<9} {'CVSS':<5} {'OBJETIVO':<24} {'HALLAZGO':<42} "
            f"{'PRIMERA VEZ':<19} {'ULTIMA VEZ':<19} {'VECES':<6} {'EVID':<8}"
        )
        print("\n" + header)
        print("-" * len(header))
        for record in records[:90]:
            print(
                f"{severity_label_es(record.get('severity', 'Info')).upper():<9} "
                f"{clean_text(record.get('cvss', ''), 5):<5} "
                f"{clean_text(record.get('target', ''), 24):<24} "
                f"{clean_text(translate_visible_text(record.get('title', '')), 42):<42} "
                f"{clean_text(record.get('first_seen', ''), 19):<19} "
                f"{clean_text(record.get('last_seen', ''), 19):<19} "
                f"{str(record.get('occurrences', 1)):<6} "
                f"{'si' if record.get('evidence_artifact') else 'no':<8}"
            )

    async def generate_html_dashboard(self) -> None:
        dashboard = ENGINE_DIR / "Dashboard.py"
        if not dashboard.exists():
            Console.warn("Dashboard.py no encontrado; dashboard HTML omitido")
            return
        Console.step("Generando dashboard HTML con Dashboard.py")
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            str(dashboard),
            cwd=str(BASE_DIR),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        started = time.monotonic()
        communicate_task = asyncio.create_task(process.communicate())
        next_heartbeat = started + 10.0
        try:
            while True:
                done, _pending = await asyncio.wait({communicate_task}, timeout=1.0)
                if communicate_task in done:
                    stdout, stderr = communicate_task.result()
                    break
                if time.monotonic() >= next_heartbeat:
                    elapsed = time.monotonic() - started
                    Console.heartbeat("dashboard", "Dashboard.py generando salida sin limite de tiempo", int(elapsed), 0)
                    self.telemetry.heartbeat("dashboard", "Dashboard.py generando salida sin limite de tiempo", int(elapsed), 0)
                    next_heartbeat = time.monotonic() + 10.0
        except asyncio.CancelledError:
            await self.external._terminate_process(process)
            raise
        except KeyboardInterrupt:
            await self.external._terminate_process(process)
            raise
        if process.returncode == 0:
            Console.ok("Dashboard.py ejecutado correctamente")
            return
        details = (stderr or stdout or b"").decode(errors="replace")
        Console.warn(f"Dashboard.py finalizo con codigo {process.returncode}: {clean_text(details, 300)}")


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Scan Titan",
        description="Escaner asincrono zero-touch de vulnerabilidades.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False,
    )
    parser._optionals.title = "opciones"
    parser.add_argument("-h", "--help", action="help", help="mostrar esta ayuda y salir")
    parser.add_argument("--version", action="version", version=SCAN_VERSION, help="mostrar la version y salir")
    parser.add_argument("-t", "--target", help="Objetivo unico opcional")
    parser.add_argument(
        "--audit-id",
        help="ID maestro opcional; zero-touch asigna y reutiliza un ID ST0 automaticamente",
    )
    parser.add_argument("--timeout", type=float, help="Timeout HTTP")
    parser.add_argument("--concurrency", type=int, help="Concurrencia HTTP global")
    parser.add_argument("--target-concurrency", type=int, help="Objetivos concurrentes")
    parser.add_argument("--max-tests", type=int, help="Maximo de pruebas por modulo")
    parser.add_argument("--max-wordlist-entries", type=int, help="Maximo de entradas cargadas por wordlist")
    parser.add_argument("--delay", type=float, help="Delay base entre peticiones HTTP")
    parser.add_argument("--module-timeout", type=int, help="Timeout por modulo; 0 = sin limite duro")
    parser.add_argument("--nmap-timeout", type=int, help="Timeout de Nmap; 0 = sin limite duro")
    parser.add_argument("--nuclei-timeout", type=int, help="Timeout de Nuclei; 0 = sin limite duro")
    parser.add_argument("--verify-tls", action="store_true", help="Verificar certificados TLS")
    parser.add_argument("--skip-external", action="store_true", help="Omitir todos los motores externos")
    parser.add_argument("--allow-cloud-ssrf", action="store_true", help="Habilitar pruebas SSRF contra metadata cloud")
    parser.add_argument(
        "--profile",
        choices=["safe", "balanced", "precision", "daily", "deep", "zero-touch"],
        help="Perfil de politica",
    )
    parser.add_argument(
        "-Full",
        "-full",
        "--full",
        dest="full",
        action="store_true",
        help=(
            "Habilita modo de maxima cobertura: perfil profundo, motores externos, browser audit, "
            "evidencias PNG, wordlists completas y timeouts sin limite duro"
        ),
    )
    parser.add_argument("--enable-browser", action="store_true", help="Forzar auditoria de navegador con Playwright")
    parser.add_argument("--disable-browser", action="store_true", help="Deshabilitar auditoria de navegador")
    parser.add_argument("--enable-zap", action="store_true", help="Forzar integracion OWASP ZAP")
    parser.add_argument("--disable-zap", action="store_true", help="Deshabilitar integracion OWASP ZAP")
    parser.add_argument("--zap-mode", choices=["passive", "baseline", "active"], help="Modo de escaneo OWASP ZAP")
    parser.add_argument("--evidence-cards", action="store_true", help="Habilitar tarjetas PNG de evidencia")
    parser.add_argument("--no-evidence-cards", action="store_true", help="Deshabilitar tarjetas PNG de evidencia")
    parser.add_argument("--console-screenshots", action="store_true", help="Habilitar captura best-effort de pantalla en Windows")
    parser.add_argument("--monitor", action="store_true", help="Abrir monitor live de solo lectura desde el lanzador raiz")
    parser.add_argument("--dashboard", action="store_true", help="Generar dashboard HTML desde reportes existentes")
    parser.add_argument("--health-check", action="store_true", help="Validar estructura, imports y herramientas externas")
    return parser


async def async_main(argv: list[str] | None = None) -> int:
    install_asyncio_noise_filter()
    args = build_argparser().parse_args(argv)
    Console.banner()
    config = RuntimeConfig(args)
    scanner = ScanTitan(config)
    return await scanner.run()


def main(argv: list[str] | None = None) -> int:
    try:
        return asyncio.run(async_main(argv))
    except KeyboardInterrupt:
        Console.warn("Interrumpido por el usuario")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
