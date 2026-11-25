"""Scan Titan ground-truth lab: recall, false positives and manual commands.

Starts an intentionally vulnerable web application on 127.0.0.1 only, runs the
real zero-touch pipeline (main.py) against it in an isolated workspace, and
compares the reported findings with a ground truth:

* expected vulnerabilities  -> must be reported (recall)
* negative controls          -> same feature implemented safely, must NOT be reported
* false-positive decoys      -> catch-all routes, WAF 403, error words; must NOT be reported

Afterwards every reported finding's ``manual_command`` is executed in Windows
PowerShell (or pwsh) and its output is checked for the proof of that finding.

Usage:  python -B tools/vuln_lab.py [--keep] [--with-external] [--timeout 900]
Exit code 0 only when recall is complete, no false positives were reported and
every manual command reproduced its proof.
"""
from __future__ import annotations

import argparse
import asyncio
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "scan_titan"))

import yaml  # noqa: E402
from aiohttp import web  # noqa: E402

from modules.common import canonical_vulnerability_family  # noqa: E402

SQL_ERROR = ("You have an error in your SQL syntax; check the manual that corresponds to your "
             "MySQL server version for the right syntax to use near ''' at line 1")
PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
ACCESS_LOG = "\n".join(
    f'10.0.0.{i} - - [10/Oct/2026:13:55:3{i} -0700] "GET /item?id={i} HTTP/1.1" 200 2326' for i in range(6))
ITEMS = {"1": "Laptop stand", "2": "USB hub", "3": "Desk lamp"}

INDEX = """<!doctype html><html><head><title>Lab Store</title></head><body>
<h1>Lab Store</h1>
<a href="/search?q=lamp">Search</a> <a href="/item?id=1">Item</a> <a href="/download?file=report.txt">Report</a>
<a href="/go?next=/item?id=2">Go</a> <a href="/hello?name=guest">Hello</a>
<a href="/safe?q=lamp">Safe search</a> <a href="/item2?id=1">Safe item</a> <a href="/static/">Static</a>
<form action="/search" method="get"><input name="q"></form>
<script src="/app.js"></script>
</body></html>"""

SPA_SHELL = ("<!doctype html><html><head><title>Lab Store</title></head><body><div id=app></div>"
             "<script>window.onerror=function(e){console.warn('error',e)};var route='{path}';</script>"
             "</body></html>")


def build_app() -> web.Application:
    async def index(request: web.Request) -> web.Response:
        response = web.Response(text=INDEX, content_type="text/html")
        response.set_cookie("sessionid", "lab-session-1234", path="/")
        return response

    async def search(request: web.Request) -> web.Response:  # V: reflected XSS (q)
        query = request.query.get("q", "")
        return web.Response(text=f"<html><body><h2>Results for {query}</h2><p>0 items</p></body></html>",
                            content_type="text/html")

    async def safe(request: web.Request) -> web.Response:  # negative: escaped output
        query = html.escape(request.query.get("q", ""))
        return web.Response(text=f"<html><body><h2>Results for {query}</h2></body></html>", content_type="text/html")

    async def item(request: web.Request) -> web.Response:  # V: SQLi (id) error + boolean
        raw = request.query.get("id", "")
        if raw.count("'") % 2 == 1 or raw.count('"') % 2 == 1:
            return web.Response(status=500, text=f"<html><body><pre>{SQL_ERROR}</pre></body></html>",
                                content_type="text/html")
        match = re.fullmatch(r"\s*(\d+)\s*(?:(and|or)\s+(\d+)\s*=\s*(\d+))?\s*(?:--.*|#.*)?", raw, re.I)
        if not match:
            return web.Response(text="<html><body>No item</body></html>", content_type="text/html")
        key, op, left, right = match.groups()
        truth = True if not op else (left == right if op.lower() == "and" else True)
        name = ITEMS.get(key) if truth else None
        return web.Response(text=f"<html><body>{name or 'No item'}</body></html>", content_type="text/html")

    async def item2(request: web.Request) -> web.Response:  # negative: parameterized lookup
        name = ITEMS.get(request.query.get("id", ""), "No item")
        return web.Response(text=f"<html><body>{html.escape(name)}</body></html>", content_type="text/html")

    async def download(request: web.Request) -> web.Response:  # V: path traversal (file)
        name = urllib.parse.unquote(request.query.get("file", ""))
        if "etc/passwd" in name.replace("\\", "/") and ".." in name:
            return web.Response(text=PASSWD, content_type="text/plain")
        if name == "report.txt":
            return web.Response(text="Quarterly report", content_type="text/plain")
        return web.Response(status=404, text="File not found", content_type="text/plain")

    async def go(request: web.Request) -> web.Response:  # V: open redirect (next)
        raise web.HTTPFound(request.query.get("next", "/"))

    async def hello(request: web.Request) -> web.Response:  # V: SSTI (name)
        name = request.query.get("name", "")
        rendered = re.sub(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", lambda m: str(int(m.group(1)) * int(m.group(2))), name)
        return web.Response(text=f"<html><body>Hello {html.escape(rendered)}</body></html>", content_type="text/html")

    async def static_index(request: web.Request) -> web.Response:  # V: directory listing
        return web.Response(text="<html><head><title>Index of /static</title></head><body><h1>Index of /static</h1>"
                                 '<a href="app.js">app.js</a> <a href="backup.sql">backup.sql</a></body></html>',
                            content_type="text/html")

    async def env_file(request: web.Request) -> web.Response:  # V: exposed .env
        return web.Response(text="APP_KEY=base64:labkey\nDB_PASSWORD=labpass\n", content_type="text/plain")

    async def access_log(request: web.Request) -> web.Response:  # V: exposed log
        return web.Response(text=ACCESS_LOG, content_type="text/plain")

    async def profile(request: web.Request) -> web.Response:  # V: CORS reflected + credentials
        origin = request.headers.get("Origin", "")
        headers = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} if origin else {}
        return web.json_response({"user": "alice"}, headers=headers)

    async def app_js(request: web.Request) -> web.Response:  # SPA bundle referencing the API
        return web.Response(text="fetch('/api/profile',{credentials:'include'}).then(r=>r.json());",
                            content_type="application/javascript")

    async def catch_all(request: web.Request) -> web.Response:  # decoys
        if request.path.endswith(".jsp"):
            return web.Response(status=403, text="<html><title>Request blocked</title>WAF</html>",
                                content_type="text/html")
        return web.Response(text=SPA_SHELL.replace("{path}", request.path), content_type="text/html")

    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/search", search)
    app.router.add_get("/safe", safe)
    app.router.add_get("/item", item)
    app.router.add_get("/item2", item2)
    app.router.add_get("/download", download)
    app.router.add_get("/go", go)
    app.router.add_get("/hello", hello)
    app.router.add_get("/static/", static_index)
    app.router.add_get("/.env", env_file)
    app.router.add_get("/access.log", access_log)
    app.router.add_get("/app.js", app_js)
    app.router.add_route("*", "/api/profile", profile)
    app.router.add_route("*", "/{tail:.*}", catch_all)
    return app


# (family, path, param) the scanner must report. param "" = any.
EXPECTED = [
    ("cross-site-scripting", "/search", "q"),
    ("sql-injection", "/item", "id"),
    ("path-traversal-lfi", "/download", "file"),
    ("open-redirect", "/go", "next"),
    ("server-side-template-injection", "/hello", "name"),
    ("environment-file-exposure", "/.env", ""),
    ("log-file-exposure", "/access.log", ""),
    ("directory-listing", "/static", ""),
    ("cors-arbitrary-origin", "/api/profile", ""),
    ("csp-missing", "", ""),
    ("clickjacking-protection-missing", "", ""),
    ("cookie-security-flags-missing", "", ""),
]
# Real issues the lab contains that are acceptable to report even if not required.
ALLOWED_EXTRA = {"x-content-type-options-missing", "referrer-policy-missing", "permissions-policy-missing",
                 "cookie-samesite-weak", "cookie-secure-missing", "cookie-security-flags-missing",
                 "cache-control-weak", "cors-arbitrary-origin", "hsts-missing", "csp-weak", "backup-file-exposure",
                 "http-cleartext", "tls-certificate-untrusted"}
# Proof each manual command output must contain, by family.
PROOF = {
    "cross-site-scripting": re.compile(r"<script|onerror=|<svg|<img|alert\(|scan_titan", re.I),
    "sql-injection": re.compile(r"sql syntax|mysql|sqlstate|laptop stand", re.I),
    "path-traversal-lfi": re.compile(r"root:x:0:0"),
    "open-redirect": re.compile(r"^location:\s*\S+", re.I | re.M),
    "server-side-template-injection": re.compile(r"\b\d{2,}\b"),
    "environment-file-exposure": re.compile(r"APP_KEY="),
    "log-file-exposure": re.compile(r'"GET /item\?id='),
    "directory-listing": re.compile(r"Index of", re.I),
    "cors-arbitrary-origin": re.compile(r"access-control-allow-origin:\s*https?://", re.I),
}
HEADER_FAMILIES = {"csp-missing", "clickjacking-protection-missing", "x-content-type-options-missing",
                   "referrer-policy-missing", "permissions-policy-missing", "hsts-missing", "cache-control-weak"}
COOKIE_FAMILIES = {"cookie-httponly-missing", "cookie-samesite-weak", "cookie-secure-missing",
                   "cookie-security-flags-missing"}


class LabServer:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.port = 0
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        runner = web.AppRunner(build_app())
        self.loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, "127.0.0.1", 0)
        self.loop.run_until_complete(site.start())
        self.port = site._server.sockets[0].getsockname()[1]
        self.ready.set()
        self.loop.run_forever()

    def start(self) -> str:
        self.thread.start()
        self.ready.wait(15)
        return f"http://127.0.0.1:{self.port}/"

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)


def lab_config(workspace: Path, with_external: bool) -> Path:
    data = yaml.safe_load((ROOT / "config" / "config.yaml").read_text(encoding="utf-8"))
    scan = data.setdefault("scan", {})
    for key in list(scan):
        if "delay" in key or "jitter" in key:
            scan[key] = 0
    scan.update({"target_concurrency": 1, "module_timeout_seconds": 240, "max_tests_per_module": 600,
                 "max_wordlist_entries": 400, "timeout_seconds": 6, "targets": [],
                 "targets_file": str(workspace / "targets.txt")})
    budgets = scan.get("module_test_budgets") or {}
    scan["module_test_budgets"] = {key: min(int(value or 0), 600) for key, value in budgets.items()}
    data.setdefault("version_intelligence", {})["auto_update"] = False
    data.setdefault("dependencies", {}).update({"auto_install_python": False, "auto_install_binaries": False})
    tools = data.setdefault("tools", {})
    if with_external:
        tools.setdefault("nuclei", {})["update_templates"] = False
    path = workspace / "config.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def run_pipeline(base_url: str, workspace: Path, with_external: bool, timeout: int) -> tuple[int, str]:
    env = dict(os.environ)
    env.update({
        "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "SCAN_TITAN_BASE_DIR": str(ROOT),
        "SCAN_TITAN_CONFIG_FILE": str(lab_config(workspace, with_external)),
        "SCAN_TITAN_REPORTS_DIR": str(workspace / "reports"),
        "SCAN_TITAN_HISTORY_DIR": str(workspace / "history"),
        "SCAN_TITAN_STATE_FILE": str(workspace / "reports" / "scan_titan_state.json"),
        "SCAN_TITAN_RUNTIME_FILE": str(workspace / "reports" / "scan_titan_runtime.json"),
        "SCAN_TITAN_RECON_FILE": str(workspace / "reports" / "Recon_Matrix.xlsx"),
        "SCAN_TITAN_TARGETS_FILE": str(workspace / "targets.txt"),
        "SCAN_TITAN_AUDIT_ID": "ST0-LAB",
    })
    (workspace / "targets.txt").write_text(base_url + "\n", encoding="utf-8")
    args = [sys.executable, "-B", str(ROOT / "main.py"), "-t", base_url, "--disable-browser",
            "--no-evidence-cards", "--profile", "zero-touch"]
    if not with_external:
        args.append("--skip-external")
    completed = subprocess.run(args, cwd=str(ROOT), env=env, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=timeout)
    log = completed.stdout + "\n" + completed.stderr
    (workspace / "pipeline.log").write_text(log, encoding="utf-8")
    return completed.returncode, log


def load_findings(workspace: Path) -> list[dict]:
    reports = sorted((workspace / "reports").glob("127.0.0.1*_*.json"), key=lambda p: p.stat().st_mtime)
    reports = [p for p in reports if not p.name.startswith(("coverage_", "recon_"))]
    if not reports:
        return []
    return json.loads(reports[-1].read_text(encoding="utf-8")).get("findings", [])


def path_of(url: str) -> str:
    return (urllib.parse.urlsplit(url or "").path or "/").rstrip("/") or "/"


def classify(findings: list[dict]) -> dict:
    matched, extra, false_positive = set(), [], []
    for item in findings:
        family = item.get("rule_id") or canonical_vulnerability_family(item)
        if family.startswith("exposed log/debug content") or "exposed log/debug content" in item.get("title", "").lower():
            family = "log-file-exposure"
        path, param = path_of(item.get("url", "")), str(item.get("param") or "").lower()
        hit = next((exp for exp in EXPECTED if exp[0] == family and (not exp[1] or path == exp[1].rstrip("/"))
                    and (not exp[2] or param == exp[2])), None)
        if hit:
            matched.add(hit)
        elif family in ALLOWED_EXTRA or (family in {e[0] for e in EXPECTED} and not path.startswith(("/safe", "/item2"))
                                         and family in HEADER_FAMILIES | COOKIE_FAMILIES):
            extra.append(item)
        else:
            false_positive.append(item)
        item["_family"] = family
    missing = [exp for exp in EXPECTED if exp not in matched]
    return {"matched": sorted(matched), "missing": missing, "extra": extra, "false_positive": false_positive}


def shell() -> list[str]:
    for name in ("powershell", "pwsh"):
        found = shutil.which(name)
        if found:
            return [found, "-NoProfile", "-NonInteractive", "-Command"]
    return []


def check_commands(findings: list[dict]) -> list[dict]:
    runner = shell()
    results = []
    for item in findings:
        command = str(item.get("manual_command") or "").strip()
        family = item.get("_family", "")
        entry = {"title": item.get("title"), "family": family, "command": command}
        if not command:
            entry.update(ok=False, reason="sin comando")
        elif not runner:
            entry.update(ok=False, reason="PowerShell no disponible")
        else:
            try:
                done = subprocess.run([*runner, command], capture_output=True, text=True, encoding="utf-8",
                                      errors="replace", timeout=60)
                output = done.stdout + done.stderr
                proof = PROOF.get(family)
                if family in HEADER_FAMILIES or family in COOKIE_FAMILIES:
                    ok = done.returncode == 0 and re.search(r"^HTTP/\d(?:\.\d)? \d{3}", output, re.M) is not None
                    reason = "cabeceras obtenidas" if ok else "sin respuesta HTTP"
                elif proof is not None:
                    ok = done.returncode == 0 and bool(proof.search(output))
                    reason = "prueba reproducida" if ok else "la salida no contiene la prueba"
                else:
                    ok = done.returncode == 0 and bool(output.strip())
                    reason = "comando ejecutado" if ok else "fallo de ejecucion"
                entry.update(ok=ok, reason=reason, exit=done.returncode, output=output[-600:])
            except subprocess.TimeoutExpired:
                entry.update(ok=False, reason="timeout 60s")
        results.append(entry)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--keep", action="store_true", help="Conservar el workspace temporal")
    parser.add_argument("--with-external", action="store_true", help="Incluir Nmap/Nuclei/ZAP")
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--report", default="", help="Ruta JSON para guardar el resultado")
    args = parser.parse_args()
    workspace = Path(tempfile.mkdtemp(prefix="scan_titan_lab_"))
    server = LabServer()
    base_url = server.start()
    started = time.monotonic()
    try:
        code, _log = run_pipeline(base_url, workspace, args.with_external, args.timeout)
        findings = load_findings(workspace)
        result = classify(findings)
        commands = check_commands(findings)
    finally:
        server.stop()
    summary = {
        "lab": base_url, "workspace": str(workspace), "pipeline_exit": code,
        "duration_s": round(time.monotonic() - started, 1), "reported": len(findings),
        "recall": f"{len(result['matched'])}/{len(EXPECTED)}",
        "missing": [list(item) for item in result["missing"]],
        "false_positives": [{"title": f.get("title"), "url": f.get("url"), "family": f.get("_family")}
                            for f in result["false_positive"]],
        "extra_real": sorted({f.get("_family") for f in result["extra"]}),
        "commands_ok": f"{sum(1 for c in commands if c['ok'])}/{len(commands)}",
        "commands_failed": [c for c in commands if not c["ok"]],
    }
    text = json.dumps(summary, indent=2, ensure_ascii=False)
    print(text)
    if args.report:
        Path(args.report).write_text(text, encoding="utf-8")
    passed = (code == 0 and not result["missing"] and not result["false_positive"]
              and all(c["ok"] for c in commands))
    print("RESULT:", "PASS" if passed else "FAIL")
    if not args.keep:
        shutil.rmtree(workspace, ignore_errors=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
