from __future__ import annotations

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
ENGINE_DIR = PROJECT_ROOT / "src" / "scan_titan"
REPORTS_DIR = PROJECT_ROOT / "audit_reports"
CONFIG_FILE = PROJECT_ROOT / "config" / "config.yaml"
TARGETS_FILE = PROJECT_ROOT / "targets" / "targets.txt"


def configure_environment() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (PROJECT_ROOT / "targets").mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("SCAN_TITAN_BASE_DIR", str(PROJECT_ROOT))
    os.environ.setdefault("SCAN_TITAN_ENGINE_DIR", str(ENGINE_DIR))
    os.environ.setdefault("SCAN_TITAN_CONFIG_FILE", str(CONFIG_FILE))
    os.environ.setdefault("SCAN_TITAN_TARGETS_FILE", str(TARGETS_FILE))
    os.environ.setdefault("SCAN_TITAN_TARGETS_DIR", str(PROJECT_ROOT / "targets"))
    os.environ.setdefault("SCAN_TITAN_WORDLISTS_DIR", str(PROJECT_ROOT / "wordlists"))
    os.environ.setdefault("SCAN_TITAN_REPORTS_DIR", str(REPORTS_DIR))
    os.environ.setdefault("SCAN_TITAN_HISTORY_DIR", str(REPORTS_DIR / "history"))
    os.environ.setdefault("SCAN_TITAN_STATE_FILE", str(REPORTS_DIR / "scan_titan_state.json"))
    os.environ.setdefault("SCAN_TITAN_RUNTIME_FILE", str(REPORTS_DIR / "scan_titan_runtime.json"))
    os.environ.setdefault("SCAN_TITAN_RECON_FILE", str(REPORTS_DIR / "Recon_Matrix.xlsx"))
    os.environ.setdefault("SCAN_TITAN_SITEMAP_FILE", str(REPORTS_DIR / "Recon_Sitemap.json"))
    os.environ.setdefault("SCAN_TITAN_KNOWLEDGE_FILE", str(PROJECT_ROOT / "data" / "scan_titan_knowledge.json"))
    os.environ.setdefault("SCAN_TITAN_DASHBOARD_FILE", str(REPORTS_DIR / "Daily_vulns_report.html"))


def engine_path_ready() -> None:
    if not (ENGINE_DIR / "Main.py").exists():
        raise RuntimeError(f"Scan Titan engine not found: {ENGINE_DIR}")
    sys.path.insert(0, str(ENGINE_DIR))


def run_monitor(argv: list[str]) -> int:
    from ScanTitan_Monitor import main as monitor_main

    sys.argv = ["ScanTitan_Monitor.py", *argv]
    return int(monitor_main())


def run_dashboard() -> int:
    from Dashboard import main as dashboard_main

    return int(dashboard_main())


def run_health_check() -> int:
    health_check = PROJECT_ROOT / "tools" / "health_check.py"
    namespace: dict[str, object] = {
        "__name__": "__scan_titan_health_check__",
        "__file__": str(health_check),
    }
    exec(health_check.read_text(encoding="utf-8"), namespace)
    return int(namespace["main"]())


def main(argv: list[str] | None = None) -> int:
    configure_environment()
    engine_path_ready()
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "--monitor":
        return run_monitor(args[1:])
    if args and args[0] == "--dashboard":
        return run_dashboard()
    if args and args[0] == "--health-check":
        return run_health_check()

    from Main import main as engine_main

    os.chdir(PROJECT_ROOT)
    return int(engine_main(args))


if __name__ == "__main__":
    raise SystemExit(main())
