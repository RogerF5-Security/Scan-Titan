from __future__ import annotations

import html
import json
import os
import re
import urllib.parse
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


class ReconSiteMapManager:
    """Builds a Burp/ZAP-style recon sitemap without mixing it with findings."""

    SCHEMA = "scan_titan_recon_sitemap_v1"
    JSON_NAME = "Recon_Sitemap.json"
    HTML_NAME = "Recon_Sitemap.html"
    MAX_ROUTES_PER_TARGET = 12000
    MAX_EXTERNAL_REFERENCES = 1500

    SOURCE_KEYS = (
        ("site_map", "crawler/zap"),
        ("sitemap_entries", "sitemap.xml"),
        ("robots_entries", "robots.txt"),
        ("discovered_paths", "descubrimiento"),
        ("unauthenticated_routes", "sin_autenticacion"),
        ("browser_routes", "browser"),
        ("browser_login_routes", "browser_login"),
        ("api_specs", "api_specs"),
        ("graphql_endpoints", "graphql"),
        ("websockets", "websocket"),
    )

    def __init__(self, reports_dir: Path, scanner_version: str = "Scan Titan") -> None:
        self.reports_dir = Path(reports_dir)
        self.scanner_version = scanner_version
        configured_json = str(os.environ.get("SCAN_TITAN_SITEMAP_FILE", "") or "").strip()
        self.json_path = Path(configured_json) if configured_json else self.reports_dir / self.JSON_NAME
        if not self.json_path.is_absolute():
            self.json_path = self.reports_dir / self.json_path
        self.html_path = self.json_path.with_name(self.HTML_NAME)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.json_path.parent.mkdir(parents=True, exist_ok=True)

    def update_target(
        self,
        *,
        target: str,
        base_url: str,
        ip: str,
        recon: dict[str, Any],
        timestamp: str,
    ) -> dict[str, Any]:
        state = self._load_state()
        target_map = self.build_target_map(target=target, base_url=base_url, ip=ip, recon=recon, timestamp=timestamp)
        previous = state.get("targets", {}).get(self._target_key(target))
        if isinstance(previous, dict):
            target_map = self._merge_with_previous(previous, target_map, timestamp)
        state.setdefault("targets", {})[self._target_key(target)] = target_map
        state["scanner"] = self.scanner_version
        state["updated_at"] = timestamp
        self._write_json(state)
        self.write_html(state)
        return {
            "json": str(self.json_path),
            "html": str(self.html_path),
            "routes": len(target_map.get("routes", [])),
            "external": len(target_map.get("external_references", [])),
        }

    def write_html(self, state: dict[str, Any] | None = None) -> Path:
        payload = state or self._load_state()
        payload["updated_at"] = payload.get("updated_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data_json = self._json_for_html(payload)
        page = self._html_template().replace("__SITEMAP_DATA__", data_json)
        temporary = self.html_path.with_suffix(self.html_path.suffix + ".tmp")
        temporary.write_text(page, encoding="utf-8")
        temporary.replace(self.html_path)
        return self.html_path

    def build_target_map(
        self,
        *,
        target: str,
        base_url: str,
        ip: str,
        recon: dict[str, Any],
        timestamp: str,
    ) -> dict[str, Any]:
        routes, external = self._collect_routes(target, base_url, ip, recon, timestamp)
        merged_routes = self._merge_route_records(routes)
        merged_external = self._merge_route_records(external)[: self.MAX_EXTERNAL_REFERENCES]
        tree = self._tree_from_routes(merged_routes)
        return {
            "target": target,
            "base_url": base_url,
            "ip": ip,
            "updated_at": timestamp,
            "route_count": len(merged_routes),
            "external_reference_count": len(merged_external),
            "status_counts": dict(Counter(str(item.get("status") or "N/D") for item in merged_routes)),
            "source_counts": self._source_counts(merged_routes),
            "routes": merged_routes[: self.MAX_ROUTES_PER_TARGET],
            "external_references": merged_external,
            "tree": tree,
        }

    def _load_state(self) -> dict[str, Any]:
        if not self.json_path.exists():
            return {
                "schema": self.SCHEMA,
                "scanner": self.scanner_version,
                "updated_at": "",
                "targets": {},
            }
        try:
            loaded = json.loads(self.json_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            loaded = {}
        if not isinstance(loaded, dict):
            loaded = {}
        if not isinstance(loaded.get("targets"), dict):
            loaded["targets"] = {}
        loaded["schema"] = self.SCHEMA
        loaded["scanner"] = loaded.get("scanner") or self.scanner_version
        return loaded

    def _write_json(self, state: dict[str, Any]) -> None:
        temporary = self.json_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.json_path)

    def _collect_routes(
        self,
        target: str,
        base_url: str,
        ip: str,
        recon: dict[str, Any],
        timestamp: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        routes: list[dict[str, Any]] = []
        external: list[dict[str, Any]] = []

        def add(raw: Any, source: str, extra: dict[str, Any] | None = None) -> None:
            record = self._normalize_record(target, base_url, ip, raw, source, timestamp, extra or {})
            if not record:
                return
            if record.pop("_external", False):
                external.append(record)
            else:
                routes.append(record)

        for key, source in self.SOURCE_KEYS:
            for item in self._as_list(recon.get(key)):
                add(item, source)
        for item in self._as_list(recon.get("endpoints")):
            source = "endpoint"
            if isinstance(item, dict):
                source = str(item.get("source") or source)
            add(item, source)
        for item in self._as_list(recon.get("wordlist_path_hits")):
            source = "wordlist"
            if isinstance(item, dict):
                source = str(item.get("module") or item.get("wordlist") or source)
            add(item, source)
        for item in self._as_list(recon.get("zap_alerts")):
            add(item, "zap_alert_context")
        return routes, external

    def _normalize_record(
        self,
        target: str,
        base_url: str,
        ip: str,
        raw: Any,
        source: str,
        timestamp: str,
        extra: dict[str, Any],
    ) -> dict[str, Any] | None:
        if isinstance(raw, dict):
            value = str(raw.get("url") or raw.get("URL") or raw.get("path") or raw.get("Path") or "").strip()
            status = str(raw.get("status") or raw.get("Status") or extra.get("status") or "").strip()
            method = str(raw.get("method") or raw.get("Method") or extra.get("method") or "GET").upper()
            classification = str(
                raw.get("classification")
                or raw.get("Classification")
                or raw.get("notes")
                or raw.get("Notes")
                or ""
            ).strip()
            redirect = str(raw.get("redirect_location") or raw.get("Redirect Location") or "").strip()
            content_type = str(raw.get("content_type") or raw.get("Content-Type") or "").strip()
            title = str(raw.get("title") or raw.get("Title") or "").strip()
            evidence = str(raw.get("evidence_summary") or raw.get("Evidence Summary") or "").strip()
            soft404 = bool(raw.get("soft404_filtered") or str(raw.get("Soft404 Filtered") or "").upper() == "YES")
        else:
            value = str(raw or "").strip()
            status = str(extra.get("status") or self._extract_status(value)).strip()
            method = str(extra.get("method") or "GET").upper()
            classification = self._extract_classification(value)
            redirect = ""
            content_type = ""
            title = ""
            evidence = ""
            soft404 = "soft404" in value.lower() or "soft-auth" in value.lower()

        value = self._clean_candidate(value)
        if not value or self._reject_non_route(value):
            return None
        url, external = self._absolute_url(base_url, value)
        if not url:
            return None
        parsed = urllib.parse.urlsplit(url)
        route, tree_path, spa_route = self._route_from_parsed(parsed)
        if not route or self._reject_path(route):
            return None
        params = sorted({key for key, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)})
        auth_hint = self._auth_hint(route, status, classification, redirect, soft404)
        return {
            "target": target,
            "ip": ip,
            "url": urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, parsed.fragment)),
            "route": route,
            "tree_path": tree_path,
            "method": method,
            "status": status or "N/D",
            "classification": classification or "observado",
            "source": source,
            "sources": [source],
            "query_params": params,
            "redirect": redirect,
            "content_type": content_type,
            "title": title,
            "evidence": evidence,
            "soft404": soft404,
            "auth_hint": auth_hint,
            "spa_route": spa_route,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "seen_count": 1,
            "_external": external,
        }

    def _absolute_url(self, base_url: str, value: str) -> tuple[str, bool]:
        base = self._origin(base_url)
        token = value
        url_match = re.search(r"https?://[^\s\"'<>|\])]+", token, flags=re.IGNORECASE)
        if url_match:
            token = url_match.group(0)
        elif token.startswith("/"):
            token = urllib.parse.urljoin(base, token)
        elif re.match(r"^[A-Za-z0-9._~%/-]+(?:\?[^\s]*)?$", token):
            token = urllib.parse.urljoin(base, "/" + token.lstrip("/"))
        else:
            return "", False

        parsed = urllib.parse.urlsplit(token)
        base_parsed = urllib.parse.urlsplit(base)
        if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.netloc:
            return "", False
        external = bool(
            base_parsed.hostname
            and parsed.hostname
            and parsed.hostname.lower() != base_parsed.hostname.lower()
        )
        return token, external

    def _route_from_parsed(self, parsed: urllib.parse.SplitResult) -> tuple[str, str, bool]:
        path = parsed.path or "/"
        fragment = parsed.fragment or ""
        spa_route = False
        if fragment.startswith(("/", "!/")):
            clean_fragment = "/" + fragment.lstrip("!/")
            route = "/#" + clean_fragment
            tree_path = "/#/" + clean_fragment.strip("/")
            spa_route = True
        else:
            route = path
            tree_path = path
        if route != "/" and route.endswith("/"):
            route = route.rstrip("/")
        if tree_path != "/" and tree_path.endswith("/"):
            tree_path = tree_path.rstrip("/")
        return route, tree_path or "/", spa_route

    def _merge_route_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged: dict[tuple[str, str], dict[str, Any]] = {}
        for record in records:
            key = (str(record.get("method") or "GET"), str(record.get("tree_path") or record.get("route") or "/").lower())
            current = merged.get(key)
            if current is None:
                merged[key] = dict(record)
                continue
            current_sources = list(current.get("sources") or [])
            for source in record.get("sources") or [record.get("source")]:
                if source and source not in current_sources:
                    current_sources.append(source)
            current["sources"] = current_sources
            current["source"] = ", ".join(current_sources[:6])
            current["status"] = self._preferred_status(current.get("status"), record.get("status"))
            current["classification"] = self._merge_text(current.get("classification"), record.get("classification"))
            current["auth_hint"] = self._merge_text(current.get("auth_hint"), record.get("auth_hint"))
            current["query_params"] = sorted(set(self._as_list(current.get("query_params")) + self._as_list(record.get("query_params"))))
            current["last_seen"] = max(str(current.get("last_seen") or ""), str(record.get("last_seen") or ""))
            current["seen_count"] = int(current.get("seen_count") or 1) + int(record.get("seen_count") or 1)
            if not current.get("redirect") and record.get("redirect"):
                current["redirect"] = record["redirect"]
            if not current.get("content_type") and record.get("content_type"):
                current["content_type"] = record["content_type"]
            if not current.get("title") and record.get("title"):
                current["title"] = record["title"]
            if len(str(record.get("evidence") or "")) > len(str(current.get("evidence") or "")):
                current["evidence"] = record.get("evidence")
        return sorted(
            merged.values(),
            key=lambda item: (
                self._status_rank(item.get("status")),
                str(item.get("tree_path") or item.get("route") or "").lower(),
            ),
        )[: self.MAX_ROUTES_PER_TARGET]

    def _merge_with_previous(
        self,
        previous: dict[str, Any],
        current: dict[str, Any],
        timestamp: str,
    ) -> dict[str, Any]:
        previous_routes = previous.get("routes", []) if isinstance(previous.get("routes"), list) else []
        by_key = {
            (str(item.get("method") or "GET"), str(item.get("tree_path") or item.get("route") or "/").lower()): item
            for item in previous_routes
            if isinstance(item, dict)
        }
        for route in current.get("routes", []):
            key = (str(route.get("method") or "GET"), str(route.get("tree_path") or route.get("route") or "/").lower())
            old = by_key.get(key)
            if isinstance(old, dict):
                route["first_seen"] = old.get("first_seen") or route.get("first_seen") or timestamp
                route["seen_count"] = int(old.get("seen_count") or 1) + 1
        current["tree"] = self._tree_from_routes(current.get("routes", []))
        return current

    def _tree_from_routes(self, routes: list[dict[str, Any]]) -> dict[str, Any]:
        root = {"name": "/", "path": "/", "routes": [], "children": {}}
        for record in routes:
            tree_path = str(record.get("tree_path") or record.get("route") or "/")
            parts = self._tree_parts(tree_path)
            if not parts:
                root["routes"].append(record)
                continue
            node = root
            current_path = ""
            for part in parts:
                current_path = self._join_tree_path(current_path, part)
                children = node.setdefault("children", {})
                node = children.setdefault(part, {"name": part, "path": current_path, "routes": [], "children": {}})
            node.setdefault("routes", []).append(record)
        return self._finalize_tree(root)

    def _finalize_tree(self, node: dict[str, Any]) -> dict[str, Any]:
        children = [self._finalize_tree(child) for child in node.get("children", {}).values()]
        route_count = len(node.get("routes", [])) + sum(int(child.get("route_count") or 0) for child in children)
        statuses = Counter(str(route.get("status") or "N/D") for route in node.get("routes", []))
        for child in children:
            statuses.update(child.get("status_counts") or {})
        return {
            "name": node.get("name", ""),
            "path": node.get("path", ""),
            "route_count": route_count,
            "status_counts": dict(statuses),
            "routes": sorted(node.get("routes", []), key=lambda item: str(item.get("route") or ""))[:200],
            "children": sorted(children, key=lambda item: str(item.get("name") or "").lower()),
        }

    def _source_counts(self, routes: list[dict[str, Any]]) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for route in routes:
            for source in self._as_list(route.get("sources") or route.get("source")):
                counts[str(source)] += 1
        return dict(counts)

    def _tree_parts(self, path: str) -> list[str]:
        if path in {"", "/"}:
            return []
        if path.startswith("/#/"):
            return ["#"] + [part for part in path[3:].split("/") if part]
        return [part for part in path.strip("/").split("/") if part]

    def _join_tree_path(self, base: str, part: str) -> str:
        if part == "#":
            return "/#"
        if base == "/#":
            return "/#/" + part
        return "/" + "/".join([item for item in [base.strip("/"), part] if item])

    def _clean_candidate(self, value: str) -> str:
        text = str(value or "").strip()
        text = text.strip("'\"`[](){}<>,;")
        text = re.sub(r"\s+\((?:20[0-9]|30[1278]|40[135]|50[0-9])[^)]*\).*$", "", text)
        text = re.sub(r"\s+->\s+.+$", "", text)
        return text.strip()

    def _reject_non_route(self, value: str) -> bool:
        text = str(value or "").strip()
        lowered = text.lower()
        if not text:
            return True
        blocked_fragments = (
            "*://",
            "*.",
            "script-src",
            "connect-src",
            "img-src",
            "frame-src",
            "default-src",
            "style-src",
            "font-src",
            "data:",
            "blob:",
            "nonce-",
            "sha256-",
            "functional map:",
            "nmap scripts:",
            "waf/cdn:",
            "perfil waf:",
            "tls protocols:",
            "http methods:",
            "zap alerts:",
        )
        if any(fragment in lowered for fragment in blocked_fragments):
            return True
        if any(char in text for char in ("\r", "\n", "\t", "<", ">", "`")):
            return True
        return False

    def _reject_path(self, path: str) -> bool:
        lowered = path.lower()
        if len(path) > 350:
            return True
        blocked = (
            "scan-titan",
            "scan_titan",
            "fuzz",
            "<script",
            "%3cscript",
            "{{",
            "${",
            " or ",
            " and ",
            "../",
            "..%2f",
            "%00",
        )
        return any(token in lowered for token in blocked)

    def _origin(self, value: str) -> str:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme and parsed.netloc:
            return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
        return value.rstrip("/") + "/"

    def _extract_status(self, value: str) -> str:
        match = re.search(r"\((20[0-9]|30[1278]|40[135]|50[0-9])\b", value)
        return match.group(1) if match else ""

    def _extract_classification(self, value: str) -> str:
        match = re.search(r"\((?:20[0-9]|30[1278]|40[135]|50[0-9])\s+([^)]{1,80})\)", value)
        return match.group(1).strip() if match else ""

    def _auth_hint(
        self,
        route: str,
        status: str,
        classification: str,
        redirect: str,
        soft404: bool,
    ) -> str:
        lowered = " ".join([route, classification, redirect]).lower()
        if soft404 or "soft_auth" in lowered or "soft-auth" in lowered:
            return "Redireccion generica a login / soft-404 autenticado"
        if str(status) in {"401", "403"}:
            return "Protegida o requiere autorizacion"
        if any(token in lowered for token in ("login", "signin", "saml", "oauth", "password", "reset")):
            return "Flujo de autenticacion"
        if any(token in lowered for token in ("admin", "dashboard", "manager", "console")):
            return "Ruta sensible para validacion de autorizacion"
        return ""

    def _preferred_status(self, old: Any, new: Any) -> str:
        old_text = str(old or "N/D")
        new_text = str(new or "N/D")
        return new_text if self._status_rank(new_text) < self._status_rank(old_text) else old_text

    def _status_rank(self, status: Any) -> int:
        return {
            "500": 0,
            "403": 1,
            "401": 2,
            "200": 3,
            "301": 4,
            "302": 5,
            "307": 6,
            "308": 7,
            "405": 8,
            "N/D": 99,
            "": 99,
        }.get(str(status or "N/D"), 50)

    def _merge_text(self, first: Any, second: Any) -> str:
        values: list[str] = []
        for value in (first, second):
            clean = str(value or "").strip()
            if clean and clean.lower() not in {item.lower() for item in values}:
                values.append(clean)
        return " | ".join(values)

    def _as_list(self, value: Any) -> list[Any]:
        if value in (None, ""):
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, (tuple, set)):
            return list(value)
        return [value]

    def _target_key(self, value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "").strip().lower())

    def _json_for_html(self, value: Any) -> str:
        return (
            json.dumps(value, ensure_ascii=False)
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )

    def _html_template(self) -> str:
        return """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Titan - Site Map de Reconocimiento</title>
<style>
:root{color-scheme:dark;--bg:#07111f;--panel:#0c1728;--panel2:#101f33;--line:#243750;--text:#e5edf7;--muted:#91a4bd;--blue:#38bdf8;--green:#22c55e;--orange:#f59e0b;--red:#ef4444;--purple:#a78bfa}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top left,#123354 0,#07111f 34%,#050b14 100%);color:var(--text);font:14px/1.48 Segoe UI,Arial,sans-serif}
code{font-family:Consolas,monospace;color:#bfdbfe}.wrap{max-width:1740px;margin:auto;padding:28px}.top{display:flex;justify-content:space-between;gap:20px;align-items:flex-end;margin-bottom:18px}
.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.16em;color:var(--blue);font-weight:800}h1{font-size:34px;margin:6px 0 4px}.note{margin:0;color:var(--muted)}.pill{display:inline-flex;align-items:center;gap:6px;padding:7px 10px;border:1px solid var(--line);border-radius:999px;background:#0a1627;color:#dbeafe;font-weight:700}
.kpis{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin:18px 0}.kpi{background:rgba(12,23,40,.92);border:1px solid var(--line);border-radius:10px;padding:14px}.kpi span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase}.kpi strong{display:block;font-size:28px;margin-top:4px}
.layout{display:grid;grid-template-columns:350px minmax(0,1fr);gap:14px}.panel{background:rgba(12,23,40,.95);border:1px solid var(--line);border-radius:12px;overflow:hidden}.panel-head{padding:14px 16px;border-bottom:1px solid var(--line);background:#0f1d30}.panel-head h2{font-size:16px;margin:0}.panel-body{padding:12px}
.search{width:100%;background:#06101d;color:var(--text);border:1px solid #38506c;border-radius:8px;padding:10px 12px;margin-bottom:10px}.targets{display:grid;gap:8px;max-height:710px;overflow:auto}.target-btn{border:1px solid transparent;background:#081525;color:var(--text);border-radius:9px;padding:11px;text-align:left;cursor:pointer}.target-btn:hover,.target-btn.active{border-color:var(--blue);background:#10243a}.target-btn strong{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.target-btn small{display:block;color:var(--muted);margin-top:3px}
.detail-top{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;padding:16px;border-bottom:1px solid var(--line);background:linear-gradient(135deg,#10243a,#0b1829)}.detail-top h2{font-size:24px;margin:3px 0}.detail-top p{margin:0;color:var(--muted);overflow-wrap:anywhere}
.badges{display:flex;flex-wrap:wrap;gap:7px;justify-content:flex-end}.badge{display:inline-flex;border:1px solid var(--line);border-radius:999px;padding:5px 8px;background:#081525;color:#dbeafe;font-size:12px;font-weight:750}.s200{border-color:var(--green);color:#bbf7d0}.s301,.s302,.s307,.s308{border-color:var(--blue);color:#bae6fd}.s401,.s403{border-color:var(--orange);color:#fde68a}.s500{border-color:var(--red);color:#fecaca}.soft{border-color:#64748b;color:#cbd5e1}.auth{border-color:var(--purple);color:#ddd6fe}
.tree-tools{display:flex;flex-wrap:wrap;gap:8px;padding:12px 16px;border-bottom:1px solid var(--line)}button{background:#0ea5e9;color:white;border:0;border-radius:8px;padding:9px 11px;font-weight:800;cursor:pointer}button.secondary{background:#1e293b;color:#dbeafe;border:1px solid #334155}
.tree{padding:8px 12px 16px;max-height:720px;overflow:auto}.node{margin-left:14px;border-left:1px solid #263a54;padding-left:12px}details{margin:5px 0}summary{cursor:pointer;list-style:none;padding:7px 8px;border-radius:8px}summary:hover{background:#10243a}summary::-webkit-details-marker{display:none}.node-title{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.folder{color:#7dd3fc;font-family:Consolas,monospace;font-weight:800}.count{color:var(--muted);font-size:12px}
.routes{display:grid;gap:8px;margin:8px 0 10px 18px}.route{border:1px solid #263a54;border-radius:9px;background:#07111e;padding:10px}.route-main{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.route-url{font-family:Consolas,monospace;color:#dbeafe;overflow-wrap:anywhere}.route-meta{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:9px;color:var(--muted);font-size:12px}.route-meta div{background:#0b1829;border:1px solid #20334b;border-radius:7px;padding:7px;overflow-wrap:anywhere}
.flat{padding:0 16px 16px}.flat table{border-collapse:collapse;width:100%;font-size:12px}.flat th,.flat td{border-bottom:1px solid #20334b;padding:8px 9px;text-align:left;vertical-align:top}.flat th{color:var(--muted);text-transform:uppercase;font-size:10px;letter-spacing:.08em;background:#0b1829;position:sticky;top:0}.flat-wrap{max-height:420px;overflow:auto;border:1px solid var(--line);border-radius:10px}
.empty{padding:24px;color:var(--muted);text-align:center}@media(max-width:1120px){.layout{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}.route-meta{grid-template-columns:1fr}}@media print{body{background:white;color:#111827}.panel,.kpi{break-inside:avoid;background:white;color:#111827}.tree{max-height:none}.targets,.tree,.flat-wrap{max-height:none}}
</style>
</head>
<body>
<main class="wrap">
<section class="top">
<div><div class="eyebrow">Scan Titan / Reconocimiento</div><h1>Site Map del objetivo</h1><p class="note">Mapa jerarquico de rutas internas, endpoints, SPA, redirects, estados HTTP y fuentes de descubrimiento.</p></div>
<div class="pill" id="updated">Actualizado: N/D</div>
</section>
<section class="kpis" id="kpis"></section>
<section class="layout">
<aside class="panel"><header class="panel-head"><h2>Objetivos</h2></header><div class="panel-body"><input id="targetSearch" class="search" placeholder="Filtrar objetivo, IP o URL..."><div class="targets" id="targets"></div></div></aside>
<section class="panel"><div id="detail"></div></section>
</section>
</main>
<script type="application/json" id="sitemapData">__SITEMAP_DATA__</script>
<script>
(()=>{'use strict';
const data=JSON.parse(document.getElementById('sitemapData').textContent);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const targets=Object.values(data.targets||{}).sort((a,b)=>String(a.target).localeCompare(String(b.target)));
let selected=targets[0]?.target||'',query='';
const $=id=>document.getElementById(id),statusClass=s=>'s'+String(s||'ND').replace(/[^0-9]/g,'').slice(0,3);
function metric(label,value){return `<article class="kpi"><span>${esc(label)}</span><strong>${esc(value)}</strong></article>`}
function badge(text,cls=''){return `<span class="badge ${cls}">${esc(text)}</span>`}
function routeBadges(route){const out=[badge(route.method||'GET'),badge(route.status||'N/D',statusClass(route.status))];if(route.soft404)out.push(badge('soft-404/login','soft'));if(route.auth_hint)out.push(badge(route.auth_hint,'auth'));return out.join('')}
function renderKpis(){const routeTotal=targets.reduce((n,t)=>n+(t.route_count||0),0),external=targets.reduce((n,t)=>n+(t.external_reference_count||0),0),withWaf=targets.filter(t=>(t.source_counts||{})['wafw00f']).length;document.getElementById('updated').textContent='Actualizado: '+(data.updated_at||'N/D');$('kpis').innerHTML=[metric('Objetivos',targets.length),metric('Rutas internas',routeTotal),metric('Referencias externas',external),metric('Fuentes activas',new Set(targets.flatMap(t=>Object.keys(t.source_counts||{}))).size),metric('WAF observado',withWaf)].join('')}
function renderTargets(){const q=query.toLowerCase();$('targets').innerHTML=targets.filter(t=>!q||JSON.stringify(t).toLowerCase().includes(q)).map(t=>`<button class="target-btn ${t.target===selected?'active':''}" data-target="${esc(t.target)}"><strong>${esc(t.target)}</strong><small>${esc(t.ip||t.base_url||'')}</small><small>${esc(t.route_count||0)} rutas · ${esc(t.external_reference_count||0)} externas</small></button>`).join('')||'<div class="empty">Sin objetivos para el filtro.</div>'}
function renderNode(node,depth=0){const statuses=Object.entries(node.status_counts||{}).filter(([k,v])=>k&&v).slice(0,5).map(([k,v])=>badge(`${k}: ${v}`,statusClass(k))).join('');const routes=(node.routes||[]).map(renderRoute).join('');const children=(node.children||[]).map(child=>renderNode(child,depth+1)).join('');const open=depth<2?' open':'';return `<details${open} class="node"><summary><span class="node-title"><span class="folder">${esc(node.name||'/')}</span><span class="count">${esc(node.route_count||0)} ruta(s)</span>${statuses}</span></summary>${routes}${children}</details>`}
function renderRoute(route){const params=(route.query_params||[]).join(', ')||'N/D';const sources=(route.sources||[route.source]).filter(Boolean).join(', ')||'N/D';return `<article class="route"><div class="route-main">${routeBadges(route)}<span class="route-url">${esc(route.route||route.url)}</span></div><div class="route-meta"><div><strong>Fuente</strong><br>${esc(sources)}</div><div><strong>Parametros</strong><br>${esc(params)}</div><div><strong>Clasificacion</strong><br>${esc(route.classification||'observado')}</div><div><strong>Ultima vez</strong><br>${esc(route.last_seen||'N/D')}</div></div>${route.redirect?`<div class="route-meta"><div><strong>Redirect</strong><br>${esc(route.redirect)}</div></div>`:''}</article>`}
function renderFlat(target){const rows=(target.routes||[]).slice(0,1200).map(r=>`<tr><td>${routeBadges(r)}</td><td><code>${esc(r.route)}</code></td><td>${esc((r.sources||[r.source]).join(', '))}</td><td>${esc((r.query_params||[]).join(', '))}</td><td>${esc(r.classification||'')}</td></tr>`).join('');return `<section class="flat"><div class="flat-wrap"><table><thead><tr><th>Estado</th><th>Ruta</th><th>Fuente</th><th>Parametros</th><th>Clasificacion</th></tr></thead><tbody>${rows||'<tr><td colspan="5">Sin rutas.</td></tr>'}</tbody></table></div></section>`}
function renderDetail(){const target=targets.find(t=>t.target===selected)||targets[0];if(!target){$('detail').innerHTML='<div class="empty">Todavia no hay sitemap de reconocimiento.</div>';return}selected=target.target;const sourceBadges=Object.entries(target.source_counts||{}).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([k,v])=>badge(`${k}: ${v}`)).join('');$('detail').innerHTML=`<div class="detail-top"><div><div class="eyebrow">Objetivo seleccionado</div><h2>${esc(target.target)}</h2><p>${esc(target.base_url||'')} ${target.ip?`· ${esc(target.ip)}`:''}</p></div><div class="badges">${badge(`${target.route_count||0} rutas`)}${badge(`${target.external_reference_count||0} externas`)}${sourceBadges}</div></div><div class="tree-tools"><button data-action="expand">Expandir todo</button><button class="secondary" data-action="collapse">Contraer todo</button><button class="secondary" data-action="print">Imprimir / PDF</button></div><div class="tree">${renderNode(target.tree||{name:'/',children:[],routes:[]})}</div>${renderFlat(target)}`;renderTargets()}
document.addEventListener('click',e=>{const t=e.target.closest('[data-target]');if(t){selected=t.dataset.target;renderDetail();return}const a=e.target.closest('[data-action]');if(!a)return;if(a.dataset.action==='expand')document.querySelectorAll('details').forEach(d=>d.open=true);if(a.dataset.action==='collapse')document.querySelectorAll('details').forEach(d=>d.open=false);if(a.dataset.action==='print')print()});
$('targetSearch').addEventListener('input',e=>{query=e.target.value;renderTargets()});
renderKpis();renderTargets();renderDetail();
})();
</script>
</body>
</html>"""
