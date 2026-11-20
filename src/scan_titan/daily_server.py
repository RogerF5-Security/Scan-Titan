"""Local-only Daily viewer with durable analyst decisions and CSRF protection."""
from __future__ import annotations

import json
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote, urlsplit

from finding_triage import load_decisions, triage_path


def create_server(report: Path, decisions_file: Path | None = None):
    report = report.resolve()
    decisions_file = decisions_file or triage_path()
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, status, body, ctype="application/json; charset=utf-8"):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def allowed(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def do_GET(self):
            if not self.allowed():
                return self.respond(403, '{}')
            if self.path == "/api/triage":
                return self.respond(200, json.dumps({"schema": "scan_titan_triage_v1", "decisions": load_decisions(decisions_file)}))
            path = urlsplit(self.path).path
            if path in {"/", "/Daily_vulns_report.html"}:
                page = report.read_text(encoding="utf-8")
                page = page.replace("connect-src 'none'", "connect-src 'self'")
                page = page.replace("</head>", "<script>window.SCAN_TITAN_TRIAGE_TOKEN=" + json.dumps(token) + ";</script></head>", 1)
                return self.respond(200, page, "text/html; charset=utf-8")
            # Evidence links remain readable, bounded to the report directory.
            candidate = (report.parent / unquote(path).lstrip("/")).resolve()
            if not candidate.is_relative_to(report.parent) or not candidate.is_file() or candidate.suffix.lower() not in {".json", ".txt", ".png", ".jpg", ".html"}:
                return self.respond(404, '{}')
            import mimetypes
            self.respond(200, candidate.read_bytes(), mimetypes.guess_type(candidate.name)[0] or "application/octet-stream")

        def do_POST(self):
            origin = f"http://127.0.0.1:{self.server.server_port}"
            if (not self.allowed() or self.path != "/api/triage" or self.headers.get("Origin") != origin
                    or not secrets.compare_digest(self.headers.get("X-ScanTitan-Token", ""), token)):
                return self.respond(403, '{}')
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 2000000:
                    return self.respond(413, '{}')
                payload = json.loads(self.rfile.read(length))
                changes = payload.get("decisions", {})
                if payload.get("schema") != "scan_titan_triage_v1" or not isinstance(changes, dict) or len(changes) > 50000:
                    raise ValueError("Invalid format")
                current = load_decisions(decisions_file)
                for key, entry in changes.items():
                    if (not isinstance(key, str) or len(key) != 64 or any(c not in '0123456789abcdef' for c in key)
                            or not isinstance(entry, dict) or entry.get("decision") not in {"discarded", "restored"}):
                        raise ValueError("Invalid decision")
                    if str(entry.get("updated_at", "")) >= str(current.get(key, {}).get("updated_at", "")):
                        current[key] = {k: str(entry.get(k, ""))[:2000] for k in ("decision", "reason", "updated_at", "url", "title")}
                decisions_file.parent.mkdir(parents=True, exist_ok=True)
                temporary = decisions_file.with_suffix(".tmp")
                temporary.write_text(json.dumps({"schema": "scan_titan_triage_v1", "decisions": current}, indent=2, ensure_ascii=False), encoding="utf-8")
                temporary.replace(decisions_file)
                self.respond(200, json.dumps({"saved": True, "decisions": current}))
            except (ValueError, TypeError, OSError) as exc:
                self.respond(400, json.dumps({"error": str(exc)}))

    # Serialize writes to avoid losing two simultaneous analyst decisions.
    from http.server import HTTPServer
    return HTTPServer(("127.0.0.1", 0), Handler)


def serve_daily(report: Path):
    server = create_server(report)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"Daily con descartes persistentes: {url}\nCtrl+C para cerrar el visor.")
    webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
