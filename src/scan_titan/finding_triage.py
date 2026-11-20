"""Persistent, endpoint-scoped analyst decisions shared by scanner and Daily."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


def value(item, name, default=""):
    return (item.get(name, default) if isinstance(item, dict) else getattr(item, name, default)) or default


def injection_family(item) -> str:
    text = " ".join(str(value(item, key)) for key in ("category", "title", "cwe")).lower()
    text = text.replace('x-xss-protection', '')
    if any(x in text for x in ("xss", "cross site scripting", "cross-site scripting", "cwe-79")):
        return "xss"
    if any(x in text for x in ("sqli", "sql injection", "inyección sql", "inyeccion sql", "cwe-89")):
        return "sqli"
    if any(x in text for x in ("path traversal", "directory traversal", "lfi", "cwe-22", "cwe-98")):
        return "lfi"
    return ""


def triage_key(item) -> str:
    parsed = urlsplit(str(value(item, "url") or value(item, "last_url")))
    # Payload changes must not resurrect the same discarded input. Origins,
    # methods and parameter names are deliberately kept separate.
    param = str(value(item, "param"))
    if not param:
        keys = {k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        if len(keys) == 1:
            param = next(iter(keys))
    identity = [parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/",
                str(value(item, "method", "GET")).upper(), param,
                injection_family(item) or str(value(item, "canonical_id") or value(item, "id") or value(item, "title"))]
    if not parsed.netloc:
        identity.append(str(value(item, "target") or value(item, "asset")))
    return hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def triage_path() -> Path:
    default = Path(os.environ.get("SCAN_TITAN_REPORTS_DIR", Path(__file__).resolve().parents[2] / "audit_reports"))
    return Path(os.environ.get("SCAN_TITAN_TRIAGE_FILE", default / "finding_triage.json"))


def load_decisions(path: Path | None = None) -> dict:
    path = path or triage_path()
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if data.get("schema") != "scan_titan_triage_v1" or not isinstance(data.get("decisions"), dict):
        raise ValueError(f"Invalid triage format: {path}")
    entries = data["decisions"]
    if len(entries) > 50000 or any(not isinstance(k, str) or len(k) != 64 or not isinstance(v, dict)
                                  or v.get("decision") not in {"discarded", "restored"} for k, v in entries.items()):
        raise ValueError("Invalid analyst decisions")
    return entries


def is_discarded(item, decisions: dict | None = None) -> bool:
    return (decisions if decisions is not None else load_decisions()).get(triage_key(item), {}).get("decision") == "discarded"
