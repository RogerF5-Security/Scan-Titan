from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path


REQUIRED_IMPORTS = ("aiohttp", "yaml", "openpyxl", "pandas", "bs4", "PIL")
OPTIONAL_IMPORTS = ("playwright", "win32gui")
EXTERNAL_TOOLS = ("nmap", "nuclei", "ffuf", "whatweb", "subfinder", "wafw00f")
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
        root / "src" / "scan_titan" / "sitemap_manager.py",
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
        found = find_project_tool(root, tool) if tool == "whatweb" else shutil.which(tool)
        if tool in {"nmap", "nuclei"}:
            ok = status(f"herramienta externa {tool}", bool(found), found or "no esta en PATH") and ok
        else:
            status(f"herramienta externa opcional {tool}", bool(found), found or "no esta en PATH")
        if tool == "whatweb" and found:
            status("whatweb oficial con JSON", whatweb_supports_json(found), found)
    zap = (
        shutil.which("zap")
        or shutil.which("zap.bat")
        or shutil.which("zaproxy")
        or next((str(path) for path in ZAP_WINDOWS_CANDIDATES if path.exists()), "")
    )
    status("herramienta externa opcional zap", bool(zap), zap or "no esta en PATH")
    return ok


def find_project_tool(root: Path, tool: str) -> str:
    candidates = []
    if tool == "whatweb":
        candidates = [
            root / "tools" / "bin" / "whatweb.cmd",
            root / "tools" / "bin" / "whatweb",
            root / "tools" / "whatweb" / "whatweb",
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


def main() -> int:
    root = project_root()
    print(f"Health-check Scan Titan: {root}")
    paths_ok = check_paths(root)
    imports_ok = check_imports()
    tools_ok = check_tools()
    if paths_ok and imports_ok and tools_ok:
        print("[OK] La plantilla Scan Titan esta lista.")
        return 0
    print("[WARN] La plantilla es usable, pero revisa advertencias antes de publicarla o lanzar un full scan.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
