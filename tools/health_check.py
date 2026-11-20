from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


REQUIRED_IMPORTS = ("aiohttp", "yaml", "openpyxl", "pandas", "bs4", "PIL", "psutil", "customtkinter", "packaging")
OPTIONAL_IMPORTS = ("playwright", "win32gui", "impacket")
EXTERNAL_TOOLS = ("nmap", "nuclei", "ffuf", "whatweb", "subfinder", "wafw00f", "katana", "httpx")
ZAP_WINDOWS_CANDIDATES = (
    Path(r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"),
    Path(r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat"),
    Path(r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat"),
)


def project_root() -> Path:
    return Path(os.environ.get("SCAN_TITAN_BASE_DIR", Path(__file__).resolve().parents[1])).resolve()


def status(label: str, ok: bool, detail: str = "") -> bool:
    marker = "OK" if ok else "WARN"
    suffix = f" - {detail}" if detail else ""
    print(f"[{marker}] {label}{suffix}")
    return ok


def check_paths(root: Path) -> bool:
    required = [
        root / "main.py",
        root / "config" / "config.yaml",
        root / "targets" / "targets.txt",
        root / "wordlists",
        root / "docs" / "web" / "index.html",
        root / "src" / "scan_titan" / "Main.py",
        root / "src" / "scan_titan" / "resource_monitor.py",
        root / "src" / "scan_titan" / "ScanTitan_Monitor.py",
        root / "src" / "scan_titan" / "monitor_ui.py",
        root / "src" / "scan_titan" / "monitor_model.py",
        root / "src" / "scan_titan" / "session_manager.py",
        root / "src" / "scan_titan" / "version_intelligence.py",
        root / "data" / "version_catalog.json",
        root / "src" / "scan_titan" / "ssh_audit.py",
        root / "src" / "scan_titan" / "modules" / "role_audit.py",
        root / "src" / "scan_titan" / "modules" / "stored_xss.py",
        root / "src" / "scan_titan" / "modules" / "race_conditions.py",
        root / "src" / "scan_titan" / "modules" / "websocket_analyzer.py",
        root / "src" / "scan_titan" / "modules" / "session_lifecycle.py",
        root / "src" / "scan_titan" / "modules" / "status_route_filter.py",
        root / "src" / "scan_titan" / "modules",
    ]
    paths_ok = all(status(str(path.relative_to(root)), path.exists()) for path in required)
    reports_ok = (root / "reports").exists() or (root / "audit_reports").exists()
    status("reports o audit_reports", reports_ok)
    return paths_ok and reports_ok


def check_imports() -> bool:
    ok = True
    for module in REQUIRED_IMPORTS:
        found = importlib.util.find_spec(module) is not None
        ok = status(f"import Python {module}", found) and ok
    for module in OPTIONAL_IMPORTS:
        found = importlib.util.find_spec(module) is not None
        status(f"import opcional {module}", found)
    return ok


def check_tools() -> bool:
    root = project_root()
    ok = True
    for tool in EXTERNAL_TOOLS:
        found = find_project_tool(root, tool) if tool in {"whatweb", "katana", "httpx"} else shutil.which(tool)
        if tool in {"nmap", "nuclei"}:
            ok = status(f"herramienta externa {tool}", bool(found), found or "no esta en PATH") and ok
        else:
            status(f"herramienta externa opcional {tool}", bool(found), found or "no esta en PATH")
        if tool == "whatweb" and found:
            status("whatweb oficial con JSON", whatweb_supports_json(found), found)
        if tool == "httpx" and found:
            status("httpx oficial de ProjectDiscovery", httpx_supports_recon(found), found)
    zap = (
        shutil.which("zap")
        or shutil.which("zap.bat")
        or shutil.which("zaproxy")
        or next((str(path) for path in ZAP_WINDOWS_CANDIDATES if path.exists()), "")
    )
    status("herramienta externa opcional zap", bool(zap), zap or "no esta en PATH")
    check_nuclei_templates()
    return ok


def check_nuclei_templates(max_age_days: int = 7) -> bool:
    """Informational: stale templates miss recent CVEs (the engine updates them
    automatically when tools.nuclei.update_templates is true)."""
    import os
    import time

    base = Path(os.environ.get("NUCLEI_TEMPLATES", "") or (Path.home() / "nuclei-templates"))
    marker = next((base / name for name in ("templates-checksum.txt", ".checksum") if (base / name).is_file()), None)
    if marker is None:
        return status("plantillas nuclei", False, f"no encontradas en {base}")
    age = (time.time() - marker.stat().st_mtime) / 86400
    return status("plantillas nuclei actualizadas", age < max_age_days,
                  f"{base} antiguedad={age:.0f} dias (limite {max_age_days})")


def find_project_tool(root: Path, tool: str) -> str:
    candidates = []
    if tool == "whatweb":
        candidates = [
            root / "tools" / "bin" / "whatweb.cmd",
            root / "tools" / "bin" / "whatweb",
            root / "tools" / "whatweb" / "whatweb",
        ]
    elif tool in {"katana", "httpx"}:
        suffix = ".exe" if os.name == "nt" else ""
        candidates = [
            root / "tools" / "bin" / f"{tool}{suffix}",
            Path.home() / "go" / "bin" / f"{tool}{suffix}",
        ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return shutil.which(tool) or ""


def whatweb_supports_json(binary: str) -> bool:
    try:
        completed = subprocess.run(
            [binary, "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=12,
            check=False,
        )
    except Exception:
        return False
    text = f"{completed.stdout}\n{completed.stderr}"
    return completed.returncode in {0, None} and "--log-json" in text and "--aggression" in text


def httpx_supports_recon(binary: str) -> bool:
    try:
        completed = subprocess.run(
            [binary, "-h"], capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    output = f"{completed.stdout}\n{completed.stderr}".lower()
    return completed.returncode == 0 and all(
        flag in output for flag in ("-tech-detect", "-status-code", "-json")
    )


def main() -> int:
    root = project_root()
    print(f"Health-check Scan Titan: {root}")
    paths_ok = check_paths(root)
    imports_ok = check_imports()
    tools_ok = check_tools()
    try:
        catalog = json.loads((root / 'data' / 'version_catalog.json').read_text(encoding='utf-8'))
        sources = catalog.get('sources', {})
        catalog_ok = catalog.get('schema') == 1 and {'retirejs', 'php_advisories', 'apache_advisories'} <= sources.keys()
        status('catalogo local de versiones', catalog_ok, f'{len(sources)} fuentes; actualizacion automatica semanal')
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        catalog_ok = status('catalogo local de versiones', False, str(exc))
    if paths_ok and imports_ok and tools_ok and catalog_ok:
        print("[OK] La plantilla Scan Titan esta lista.")
        return 0
    print("[WARN] La plantilla es usable, pero revisa advertencias antes de publicarla o lanzar un full scan.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
