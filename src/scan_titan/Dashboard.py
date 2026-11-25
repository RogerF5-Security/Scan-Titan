from __future__ import annotations

import datetime as dt
import glob
import html
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from quality_rules import finding_quality_exclusion
from finding_triage import injection_family, load_decisions, triage_key
from daily_report import render_daily
from daily_history import build_timeline, logo_data_uri
from daily_ui import intelligence_model
from modules.injection_validation import proof_text, replay_command, without_parameter
from urllib.parse import parse_qsl, urlsplit

try:
    from openpyxl import load_workbook
except Exception:
    load_workbook = None  # type: ignore[assignment]

try:
    from modules.common import (
        category_label_es,
        confidence_label_es,
        evidence_strength_label_es,
        false_positive_risk_label_es,
        normalize_severity,
        translate_visible_text,
    )
except Exception:
    def normalize_severity(value: Any) -> str:  # type: ignore[no-redef]
        mapping = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info",
                   "critica": "Critical", "crítica": "Critical", "alta": "High", "media": "Medium", "baja": "Low"}
        return mapping.get(str(value or "Info").strip().lower(), "Info")

    def translate_visible_text(value: Any) -> str:  # type: ignore[no-redef]
        return "" if value is None else str(value)

    def category_label_es(value: Any) -> str:  # type: ignore[no-redef]
        return "" if value is None else str(value)

    def confidence_label_es(value: Any) -> str:  # type: ignore[no-redef]
        return "" if value is None else str(value)

    def evidence_strength_label_es(value: Any) -> str:  # type: ignore[no-redef]
        return "" if value is None else str(value)

    def false_positive_risk_label_es(value: Any) -> str:  # type: ignore[no-redef]
        return "" if value is None else str(value)


DASHBOARD_VERSION = "22.5.0-community"
SCANNER_FALLBACK = "TITAN v22.5.0 COMMUNITY ZERO-TOUCH"
BASE_DIR = Path(os.environ.get("SCAN_TITAN_BASE_DIR", Path(__file__).resolve().parents[2])).resolve()
REPORTS_DIR = Path(os.environ.get("SCAN_TITAN_REPORTS_DIR", BASE_DIR / "reports")).resolve()
CONFIG_FILE = Path(os.environ.get("SCAN_TITAN_CONFIG_FILE", BASE_DIR / "config" / "config.yaml")).resolve()
CARPETA_REPORTES = str(REPORTS_DIR)
ARCHIVO_SALIDA = str(
    Path(os.environ.get("SCAN_TITAN_DASHBOARD_FILE", REPORTS_DIR / "Daily_vulns_report.html")).resolve()
)
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
SEVERITY_BASE_CVSS = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}
REPORT_COLUMNS = [
    "Fecha", "Timestamp", "Scanner", "Asset", "Vuln_ID", "Target", "Severidad", "Titulo",
    "Categoria", "URL", "Endpoint", "Param", "Method", "Payload", "HTTP", "Evidence",
    "Manual_Command", "Sources", "Confidence", "Evidence_Strength", "False_Positive_Risk",
    "CWE", "OWASP", "CVSS", "Impact", "Remediation", "Recommendation", "Evidence_Artifact",
    "Console_Artifact", "Browser_Artifact", "Affected_Locations", "Validation",
]
RECON_FILE = Path(os.environ.get("SCAN_TITAN_RECON_FILE", REPORTS_DIR / "Recon_Matrix.xlsx")).resolve()

SEVERITY_ALIASES = {
    "CRITICA": "CRITICAL",
    "CRÍTICA": "CRITICAL",
    "ALTA": "HIGH",
    "MEDIA": "MEDIUM",
    "BAJA": "LOW",
    "INFORMATIVA": "INFO",
    "INFORMATIVO": "INFO",
}

DETAIL_ALIASES = {
    "Vulnerability ID": ("Vulnerability ID", "ID de Vulnerabilidad", "ID Vulnerabilidad"),
    "Category": ("Category", "Categoria", "Categoría"),
    "URL": ("URL",),
    "Endpoint": ("Endpoint",),
    "Param": ("Param", "Parametro", "Parámetro"),
    "Method": ("Method", "Metodo", "Método"),
    "Payload": ("Payload",),
    "HTTP": ("HTTP",),
    "Evidence": ("Evidence", "Evidencia"),
    "Manual Test": ("Manual Test", "Prueba Manual", "Prueba manual"),
    "Source": ("Source", "Fuente"),
    "Confidence": ("Confidence", "Confianza"),
    "Evidence Strength": ("Evidence Strength", "Fuerza de Evidencia", "Fuerza de evidencia"),
    "False Positive Risk": ("False Positive Risk", "Riesgo de Falso Positivo", "Riesgo de falso positivo"),
    "CWE": ("CWE",),
    "OWASP": ("OWASP",),
    "CVSS": ("CVSS",),
    "Impact": ("Impact", "Impacto"),
    "Remediation": ("Remediation", "Remediacion", "Remediación"),
    "Recommendation": ("Recommendation", "Recomendacion", "Recomendación"),
    "Evidence Artifact": ("Evidence Artifact", "Artefacto de Evidencia", "Artefacto de evidencia"),
    "Console Artifact": ("Console Artifact", "Artefacto de Consola", "Artefacto de consola"),
    "Browser Evidence": ("Browser Evidence", "Evidencia Browser", "Evidencia navegador"),
    "Affected Locations": ("Affected Locations", "Ubicaciones Afectadas", "Ubicaciones afectadas"),
}


def configurar_salida_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


configurar_salida_utf8()


def _text(value: Any) -> str:
    return "" if value is None else html.unescape(str(value)).strip()


def _list_text(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_text(item) for item in value if _text(item))
    return _text(value)


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _timestamp_text(value: Any) -> str:
    parsed = pd.to_datetime(value, errors="coerce")
    return "" if pd.isna(parsed) else parsed.strftime("%Y-%m-%d %H:%M:%S")


def _json_for_html(value: Any) -> str:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            .replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _empty_record() -> dict[str, Any]:
    return {column: "" for column in REPORT_COLUMNS}


def _severity_code(value: Any) -> str:
    normalized = _text(value).upper()
    normalized = normalized.replace("Í", "I")
    mapped = SEVERITY_ALIASES.get(normalized, normalized)
    return normalize_severity(mapped).upper()


def _detail(details: dict[str, str], key: str, default: str = "") -> str:
    for alias in DETAIL_ALIASES.get(key, (key,)):
        if alias in details and _text(details.get(alias)):
            return _text(details.get(alias))
    return default


def _display_es(value: Any) -> str:
    return translate_visible_text(_text(value))


def _confidence_es(value: Any) -> str:
    return confidence_label_es(value) or _text(value)


def _evidence_strength_es(value: Any) -> str:
    return evidence_strength_label_es(value) or _text(value)


def _fp_risk_es(value: Any) -> str:
    return false_positive_risk_label_es(value) or _text(value)


def parsear_reporte(filepath: str) -> list[dict[str, Any]]:
    """Parse legacy numbered TXT reports without losing compatibility."""
    filename = os.path.basename(filepath)
    try:
        content = Path(filepath).read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        print(f"[!] Error leyendo {filename}: {exc}")
        return []
    scanner_match = re.search(r"TITAN v(\d+(?:\.\d+)*)\s+([A-Z]+(?:-[A-Z]+)*(?:\s+[A-Z]+(?:-[A-Z]+)*)*)", content, re.I)
    scanner = f"TITAN v{scanner_match.group(1)} {scanner_match.group(2).strip()}" if scanner_match else "TITAN"
    target_match = re.search(r"(?:Target|Objetivo):\s*(.+)", content)
    target = _text(target_match.group(1)) if target_match else ""
    timestamp_match = re.search(r"(?:Date|Fecha):\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", content)
    date_match = re.search(r"_(\d{4}-\d{2}-\d{2})\.txt", filename)
    timestamp = timestamp_match.group(1) if timestamp_match else f"{date_match.group(1) if date_match else dt.date.today().isoformat()} 00:00:00"
    target = target or (filename.rsplit("_", 1)[0] if "_" in filename else "Unknown_Asset")
    findings: list[dict[str, Any]] = []
    for block in re.split(r"\n[─=-]{40,}\n", content):
        match = re.match(
            r"\[(\d+)\]\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO|CRITICA|CRÍTICA|ALTA|MEDIA|BAJA|INFORMATIVA|INFORMATIVO)\s*\]\s+(.+)",
            block.strip(),
            re.I,
        )
        if not match:
            continue
        index, severity, title = match.groups()
        details: dict[str, str] = {}
        for line in block.splitlines()[1:]:
            line = line.strip()
            if ":" in line and not line.startswith("http"):
                key, value = line.split(":", 1)
                if key.strip() and value.strip():
                    details[key.strip()] = value.strip()
        record = _empty_record()
        severity_code = _severity_code(severity)
        record.update({
            "Fecha": timestamp[:10], "Timestamp": timestamp, "Scanner": scanner, "Asset": target,
            "Vuln_ID": _detail(details, "Vulnerability ID") or f"LEGACY-{index}-{title}", "Target": target,
            "Severidad": severity_code, "Titulo": _display_es(title), "Categoria": category_label_es(_detail(details, "Category", "Desconocida")),
            "URL": _detail(details, "URL"), "Endpoint": _detail(details, "Endpoint"), "Param": _detail(details, "Param"),
            "Method": _detail(details, "Method"), "Payload": _detail(details, "Payload", details.get("Attack", "")),
            "HTTP": _detail(details, "HTTP"), "Evidence": _display_es(_detail(details, "Evidence")),
            "Manual_Command": _detail(details, "Manual Test"), "Sources": _detail(details, "Source", scanner),
            "Confidence": _detail(details, "Confidence"), "Evidence_Strength": _detail(details, "Evidence Strength"),
            "False_Positive_Risk": _detail(details, "False Positive Risk"), "CWE": _detail(details, "CWE"),
            "OWASP": _detail(details, "OWASP"), "CVSS": _detail(details, "CVSS"), "Impact": _display_es(_detail(details, "Impact")),
            "Remediation": _display_es(_detail(details, "Remediation")), "Recommendation": _display_es(_detail(details, "Recommendation")),
            "Evidence_Artifact": _detail(details, "Evidence Artifact"), "Console_Artifact": _detail(details, "Console Artifact"),
            "Browser_Artifact": _detail(details, "Browser Evidence"),
            "Affected_Locations": _detail(details, "Affected Locations"),
        })
        findings.append(record)
    return findings


def parsear_reporte_json(filepath: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(Path(filepath).read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []
    if not isinstance(data, dict) or data.get("schema") != "scan_titan_target_report_v1":
        return []
    timestamp = _text(data.get("date")) or f"{dt.date.today().isoformat()} 00:00:00"
    target = _text(data.get("target") or data.get("url") or "Unknown_Asset")
    ip, scanner = _text(data.get("ip")), _text(data.get("scanner")) or SCANNER_FALLBACK
    parsed: list[dict[str, Any]] = []
    for finding in data.get("findings", []) or []:
        if not isinstance(finding, dict) or finding_quality_exclusion(finding):
            continue
        record = _empty_record()
        record.update({
            "Fecha": timestamp[:10], "Timestamp": timestamp, "Scanner": scanner,
            "Asset": _text(finding.get("asset") or ip or target),
            "Vuln_ID": _text(finding.get("canonical_id") or finding.get("fingerprint") or finding.get("title")),
            "Target": target, "Severidad": _severity_code(finding.get("severity") or "Info"),
            "Titulo": _display_es(finding.get("title") or "Vulnerabilidad sin titulo"),
            "Categoria": category_label_es(finding.get("category") or "Desconocida"), "URL": _text(finding.get("url")),
            "Endpoint": _text(finding.get("endpoint")), "Param": _text(finding.get("param")),
            "Method": _text(finding.get("method")), "Payload": _text(finding.get("payload")),
            "HTTP": _text(finding.get("http")), "Evidence": _display_es(finding.get("evidence")),
            "Manual_Command": _text(finding.get("manual_command")),
            "Sources": _list_text(finding.get("correlated_sources") or [finding.get("source")]),
            "Confidence": _text(finding.get("confidence")), "Evidence_Strength": _text(finding.get("evidence_strength")),
            "False_Positive_Risk": _text(finding.get("false_positive_risk")), "CWE": _text(finding.get("cwe")),
            "OWASP": _text(finding.get("owasp")), "CVSS": finding.get("cvss", ""), "Impact": _display_es(finding.get("impact")),
            "Remediation": _display_es(finding.get("remediation")), "Recommendation": _display_es(finding.get("recommendation")),
            "Evidence_Artifact": _text(finding.get("evidence_artifact")), "Console_Artifact": _text(finding.get("console_artifact")),
            "Browser_Artifact": _text(finding.get("browser_artifact")),
            "Affected_Locations": _list_text(finding.get("affected_locations")),
            "Validation": finding.get('validation') or {},
        })
        parsed.append(record)
    return parsed


def obtener_dataframe() -> pd.DataFrame:
    reports = Path(CARPETA_REPORTES)
    reports.mkdir(parents=True, exist_ok=True)
    data: list[dict[str, Any]] = []
    parsed_files = 0
    for filepath in sorted(glob.glob(str(reports / "*.json"))):
        rows = parsear_reporte_json(filepath)
        if rows:
            parsed_files += 1
            data.extend(rows)
    source = "JSON"
    if not data:
        source = "TXT"
        for filepath in sorted(glob.glob(str(reports / "*.txt"))):
            rows = parsear_reporte(filepath)
            if rows:
                parsed_files += 1
                data.extend(rows)
    if not data:
        print("[!] No se encontraron reportes de vulnerabilidades compatibles")
        return pd.DataFrame(columns=REPORT_COLUMNS)
    frame = pd.DataFrame(data)
    for column in REPORT_COLUMNS:
        if column not in frame.columns:
            frame[column] = ""
    frame["Fecha"] = pd.to_datetime(frame["Fecha"], errors="coerce")
    frame["Timestamp"] = pd.to_datetime(frame["Timestamp"], errors="coerce")
    frame = frame.dropna(subset=["Fecha", "Timestamp"]).sort_values("Timestamp")
    frame = frame.drop_duplicates(subset=["Fecha", "Asset", "Vuln_ID"], keep="last")
    frame = frame.sort_values("Timestamp", ascending=False).reset_index(drop=True)
    print(f"[+] Dashboard: {len(frame)} observaciones diarias desde {parsed_files} reportes {source}")
    return frame


def cargar_estado_hallazgos() -> dict[str, dict[str, Any]] | None:
    path = Path(CARPETA_REPORTES) / "scan_titan_state.json"
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None
    findings = state.get("findings") if isinstance(state, dict) else None
    return findings if isinstance(findings, dict) else None


def cargar_claves_activas() -> set[tuple[str, str]] | None:
    records = cargar_estado_hallazgos()
    if records is None:
        return None
    return {(_text(r.get("asset") or r.get("target")), _text(r.get("canonical_id"))) for r in records.values()
            if isinstance(r, dict) and _text(r.get("state")).upper() == "ACTIVE" and _text(r.get("canonical_id"))}


def cargar_runtime() -> dict[str, Any]:
    path = Path(CARPETA_REPORTES) / "scan_titan_runtime.json"
    if not path.exists():
        return {}
    try:
        runtime = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        return runtime if isinstance(runtime, dict) else {}
    except Exception:
        return {}


def _risk_score(record: dict[str, Any]) -> float:
    severity = _text(record.get("severity") or record.get("Severidad") or "INFO").upper()
    cvss = _float(record.get("cvss") if "cvss" in record else record.get("CVSS"))
    cvss = cvss if 0 < cvss <= 10 else SEVERITY_BASE_CVSS.get(severity, 0.0)
    confidence = _text(record.get("confidence") or record.get("Confidence")).lower()
    evidence = _text(record.get("evidence_strength") or record.get("Evidence_Strength")).lower()
    fp_risk = _text(record.get("false_positive_risk") or record.get("False_Positive_Risk")).lower()
    occurrences = max(1, _int(record.get("occurrences"), 1))
    category = _text(record.get("category") or record.get("Categoria")).lower()
    factors = [
        {"high": 1.0, "medium": .78, "low": .52}.get(confidence, .72),
        {"strong": 1.08, "medium": .94, "weak": .72}.get(evidence, .90),
        {"low": 1.0, "medium": .84, "high": .58}.get(fp_risk, .88),
        1.08 if any(token in category for token in ("external", "network", "cors", "tls")) else 1.0,
        1.0 + min(math.log2(occurrences), 4.0) * .035,
        _float(record.get("asset_criticality_factor"), 1.0),
    ]
    evidence_ratio = min(1.0, max(0.0, (cvss / 10) * math.prod(factors)))
    bands = {"CRITICAL": (82.0, 100.0), "HIGH": (62.0, 81.9), "MEDIUM": (34.0, 61.9), "LOW": (8.0, 33.9), "INFO": (0.0, 0.0)}
    floor, ceiling = bands.get(severity, (0.0, 25.0))
    return round(floor + (ceiling - floor) * evidence_ratio, 1)


def _asset_criticality_config() -> tuple[str, dict[str, str]]:
    path = CONFIG_FILE
    try:
        config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return "Medio", {}
    dashboard = config.get("dashboard") if isinstance(config, dict) else {}
    dashboard = dashboard if isinstance(dashboard, dict) else {}
    reporting = config.get("reporting", {}) if isinstance(config, dict) else {}
    technical = reporting.get("technical_detail", {}) if isinstance(reporting, dict) else {}
    default = _text(dashboard.get("default_asset_criticality") or (technical.get("asset_criticality") if isinstance(technical, dict) else "Medio")) or "Medio"
    per_asset = dashboard.get("asset_criticality", {})
    return default, ({_text(key): _text(value) for key, value in per_asset.items()} if isinstance(per_asset, dict) else {})


def calcular_risk_score(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["Target", "RiskScore"])
    grouped: dict[str, list[float]] = defaultdict(list)
    for record in df.to_dict("records"):
        grouped[_text(record.get("Target"))].append(_risk_score(record))
    rows = [{"Target": target, "RiskScore": round(min(100.0, max(scores) + .05 * sum(sorted(scores, reverse=True)[1:])), 1)}
            for target, scores in grouped.items()]
    return pd.DataFrame(rows).sort_values("RiskScore", ascending=False).reset_index(drop=True)


def _artifact_href(value: Any) -> str:
    raw = _text(value)
    if not raw:
        return ""
    try:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = (Path(CARPETA_REPORTES) / candidate).resolve()
        return candidate.resolve().relative_to(Path(ARCHIVO_SALIDA).resolve().parent).as_posix()
    except Exception:
        return ""


def _record_from_state(record: dict[str, Any], latest: dict[str, Any], cutoff: str) -> dict[str, Any]:
    state = _text(record.get("state") or "ACTIVE").upper()
    first_seen = _timestamp_text(record.get("first_seen") or latest.get("Timestamp"))
    last_seen = _timestamp_text(record.get("last_seen") or latest.get("Timestamp"))
    regression_count, reappeared = _int(record.get("regression_count")), _timestamp_text(record.get("reappeared_at"))
    status = "NOT_SEEN" if state == "NOT_SEEN" else ("REGRESSION" if regression_count and reappeared[:10] == cutoff else ("NEW" if first_seen[:10] == cutoff else "RECURRING"))
    severity = _severity_code(record.get("severity") or latest.get("Severidad") or "Info")
    confidence = _text(record.get("confidence") or latest.get("Confidence") or "unknown").lower()
    evidence_strength = _text(record.get("evidence_strength") or latest.get("Evidence_Strength") or "unknown").lower()
    fp_risk = _text(record.get("false_positive_risk") or latest.get("False_Positive_Risk") or "unknown").lower()
    title = _display_es(record.get("title") or latest.get("Titulo") or "Hallazgo sin titulo")
    candidate = ("potential cve" in title.lower() or "inferred from service version" in title.lower()
                 or fp_risk == "high" or record.get('source') == 'version_intelligence'
                 or 'version_intelligence' in (record.get('correlated_sources') or []))
    row: dict[str, Any] = {
        "id": _text(record.get("canonical_id") or latest.get("Vuln_ID")), "fingerprint": _text(record.get("fingerprint")),
        "target": _text(record.get("target") or latest.get("Target")), "asset": _text(record.get("asset") or latest.get("Asset")),
        "severity": severity, "status": status, "state": state,
        "quality": "INFORMATIONAL" if severity == "INFO" else ("CANDIDATE" if candidate else "VALIDATED"),
        "title": title, "category": category_label_es(record.get("category") or latest.get("Categoria") or "Desconocida"),
        "url": _text(record.get("last_url") or latest.get("URL")), "endpoint": _text(record.get("endpoint") or latest.get("Endpoint")),
        "param": _text(record.get("param") or latest.get("Param")), "method": _text(record.get("method") or latest.get("Method")), "payload": _text(latest.get("Payload")),
        "http": _text(latest.get("HTTP")), "evidence": _display_es(record.get("last_evidence") or latest.get("Evidence")),
        "manual_command": _text(record.get("manual_command") or latest.get("Manual_Command")),
        "sources": _list_text(record.get("correlated_sources") or latest.get("Sources")),
        "scanner": _text(latest.get("Scanner")) or SCANNER_FALLBACK, "confidence": confidence,
        "evidence_strength": evidence_strength, "false_positive_risk": fp_risk,
        "cwe": _text(record.get("cwe") or latest.get("CWE")), "owasp": _text(record.get("owasp") or latest.get("OWASP")),
        "cvss": _float(record.get("cvss") or latest.get("CVSS")), "impact": _display_es(record.get("impact") or latest.get("Impact")),
        "remediation": _display_es(record.get("remediation") or latest.get("Remediation")),
        "recommendation": _display_es(record.get("recommendation") or latest.get("Recommendation")),
        "first_seen": first_seen, "last_seen": last_seen, "occurrences": max(1, _int(record.get("occurrences"), 1)),
        "regression_count": regression_count, "state_changed_at": _timestamp_text(record.get("state_changed_at")),
        "affected_locations": _text(latest.get("Affected_Locations")),
        "evidence_artifact": _text(record.get("evidence_artifact") or latest.get("Evidence_Artifact")),
        "console_artifact": _text(record.get("console_artifact") or latest.get("Console_Artifact")),
        "browser_artifact": _text(record.get("browser_artifact") or latest.get("Browser_Artifact")),
    }
    row["evidence_href"] = _artifact_href(row["evidence_artifact"])
    row["console_href"] = _artifact_href(row["console_artifact"])
    row["browser_href"] = _artifact_href(row["browser_artifact"])
    row["risk"] = _risk_score(row)
    row['validation'] = record.get('validation') or {}
    if not isinstance(row['validation'], dict):
        row['validation'] = {}
    family = injection_family(record)
    if family:
        query_names = {name for name, _ in parse_qsl(urlsplit(row['url']).query, keep_blank_values=True)}
        if not row['param'] and len(query_names) == 1:
            row['param'] = next(iter(query_names))
        if (row['method'] or 'GET').upper() == 'GET' and row['param'] in query_names:
            validation = row['validation']
            confirmed = validation.get('state') == 'CONFIRMED'
            requests = validation.get('requests') or {'baseline_url': without_parameter(row['url'], row['param']), 'probe_url': row['url']}
            # A confirmed replay prints the literal proof; a historical alert only compares control and probe.
            expected = validation.get('reason') or ('validacion diferencial confirmada' if confirmed
                                                    else 'alerta historica pendiente de validacion diferencial')
            proof = proof_text(family, validation, row['payload']) if confirmed else ""
            row['manual_command'] = replay_command(requests, expected, proof)
    row['triage_key'] = triage_key({**record, 'url': row['url'], 'param': row['param'], 'method': row['method']})
    row['rule'] = _text(record.get('rule_id')) or _rule_of(record)
    return row


def _rule_of(record: dict[str, Any]) -> str:
    try:
        from modules.common import canonical_vulnerability_family
        return canonical_vulnerability_family({**record, 'url': record.get('url') or record.get('last_url', '')})
    except Exception:
        return _text(record.get('title'))


def _fallback_rows(df: pd.DataFrame, cutoff: str) -> list[dict[str, Any]]:
    tracking = df.groupby(["Asset", "Vuln_ID"])["Timestamp"].agg(["min", "max"]).reset_index()
    latest = df.sort_values("Timestamp").drop_duplicates(["Asset", "Vuln_ID"], keep="last").merge(tracking, on=["Asset", "Vuln_ID"], how="left")
    rows = []
    for item in latest.to_dict("records"):
        synthetic = {"target": item.get("Target"), "asset": item.get("Asset"), "canonical_id": item.get("Vuln_ID"),
                     "category": item.get("Categoria"), "severity": item.get("Severidad"), "title": item.get("Titulo"),
                     "first_seen": item.get("min"), "last_seen": item.get("max"), "state": "ACTIVE",
                     "confidence": item.get("Confidence"), "evidence_strength": item.get("Evidence_Strength"),
                     "false_positive_risk": item.get("False_Positive_Risk"), "last_url": item.get("URL"),
                     "last_evidence": item.get("Evidence"), "manual_command": item.get("Manual_Command"),
                     "correlated_sources": item.get("Sources"), "cwe": item.get("CWE"), "owasp": item.get("OWASP"),
                     "cvss": item.get("CVSS"), "impact": item.get("Impact"), "remediation": item.get("Remediation"),
                     "recommendation": item.get("Recommendation"), "evidence_artifact": item.get("Evidence_Artifact"),
                     "console_artifact": item.get("Console_Artifact"), "browser_artifact": item.get("Browser_Artifact"),
                     "validation": item.get("Validation") or {}}
        row = _record_from_state(synthetic, item, cutoff)
        if finding_quality_exclusion(synthetic):
            row.update(state='PENDING', status='PENDING', quality='CANDIDATE')
        rows.append(row)
    return rows


def _tool_health(runtime: dict[str, Any]) -> dict[str, Any]:
    latest: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in runtime.get("external_tools", []):
        if isinstance(item, dict):
            latest[(_text(item.get("target")), _text(item.get("tool")), _text(item.get("profile")))] = item
    status_labels = {
        "finished": "finalizado",
        "failed": "fallido",
        "timeout": "timeout",
        "error": "error",
        "degraded": "degradado",
        "running": "en ejecucion",
        "skipped": "omitido",
        "unknown": "desconocido",
    }
    raw_counts = Counter(_text(item.get("status") or "unknown").lower() for item in latest.values())
    counts = {status_labels.get(key, key): value for key, value in raw_counts.items()}
    degraded = [{"tool": _text(item.get("tool")), "profile": _text(item.get("profile")), "target": _text(item.get("target")),
                 "status": status_labels.get(_text(item.get("status")).lower(), _text(item.get("status"))),
                 "error": _brief_error(item.get("error"))} for item in latest.values()
                if _text(item.get("status")).lower() in {"degraded", "failed", "timeout", "error"}]
    return {"counts": dict(counts), "total": len(latest), "degraded": degraded[:20]}


def _worksheet_rows(sheet: Any, headers: list[str], header_row: int = 6, limit: int = 1000) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    try:
        max_row = min(sheet.max_row, header_row + max(1, int(limit)))
        for row in sheet.iter_rows(min_row=header_row + 1, max_row=max_row, values_only=True):
            record = {header: _list_text(value) for header, value in zip(headers, row)}
            if any(record.values()):
                rows.append(record)
    except Exception:
        return rows
    return rows


def _split_recon_cell(value: Any, limit: int = 80) -> list[str]:
    raw = _text(value)
    if not raw:
        return []
    if raw.startswith("[") or raw.startswith("{"):
        try:
            parsed = json.loads(raw.replace("'", '"'))
            if isinstance(parsed, list):
                return [_text(item) for item in parsed[:limit] if _text(item)]
        except Exception:
            pass
    parts = re.split(r"\s*\|\s*|\n|,\s+(?=https?://|/[A-Za-z0-9_.~/-]|[A-Z][A-Za-z0-9_. -]{2,})", raw)
    clean = []
    for item in parts:
        text = _display_es(item).strip()
        if text and text not in clean:
            clean.append(text)
        if len(clean) >= limit:
            break
    return clean


def cargar_recon_modelo() -> dict[str, Any]:
    if load_workbook is None or not RECON_FILE.exists():
        return {"available": False, "targets": [], "hits": [], "summary": {}}
    try:
        workbook = load_workbook(RECON_FILE, data_only=True, read_only=True)
        main_sheet = workbook["Recon Matrix"] if "Recon Matrix" in workbook.sheetnames else workbook[workbook.sheetnames[0]]
        main_headers = [_text(cell.value) for cell in main_sheet[6] if _text(cell.value)]
        targets = _worksheet_rows(main_sheet, main_headers, limit=500)
        hit_rows: list[dict[str, str]] = []
        if "Wordlist Hits" in workbook.sheetnames:
            hit_sheet = workbook["Wordlist Hits"]
            hit_headers = [_text(cell.value) for cell in hit_sheet[6] if _text(cell.value)]
            hit_rows = _worksheet_rows(hit_sheet, hit_headers, limit=2000)
        workbook.close()
    except Exception:
        return {"available": False, "targets": [], "hits": [], "summary": {}}

    normalized_targets = []
    for row in targets:
        target = _text(row.get("Target"))
        if not target:
            continue
        normalized_targets.append(
            {
                "target": target,
                "ip": _text(row.get("IP")),
                "tipo": _text(row.get("Tipo")),
                "url": _text(row.get("URL Base")),
                "puertos": _split_recon_cell(row.get("Puertos Expuestos"), 120),
                "servicios": _split_recon_cell(row.get("Servicios"), 120),
                "tecnologias": _split_recon_cell(row.get("Tecnologias"), 120),
                "rutas": _split_recon_cell(row.get("Enrutamiento/Endpoints descubiertos"), 180),
                "login": _split_recon_cell(row.get("Formularios de Login"), 80),
                "js": _split_recon_cell(row.get("Librerias JS"), 100),
                "cookies": _display_es(row.get("Estado de Cookies")),
                "headers": _split_recon_cell(row.get("Headers Expuestos"), 120),
                "waf": _split_recon_cell(row.get("WAF/CDN"), 40),
                "wafw00f": _display_es(row.get("WAF wafw00f")),
                "perfil_waf": _display_es(row.get("Perfil WAF")),
                "subdominios": _split_recon_cell(row.get("Subdominios"), 160),
                "whatweb": _split_recon_cell(row.get("WhatWeb Tecnologias"), 120),
                "ultima": _text(row.get("Ultima Ejecucion")),
            }
        )

    normalized_hits = []
    for row in hit_rows:
        normalized_hits.append(
            {
                "timestamp": _text(row.get("Timestamp")),
                "target": _text(row.get("Target")),
                "status": _text(row.get("Status")),
                "url": _text(row.get("URL")),
                "path": _text(row.get("Path")),
                "clasificacion": _display_es(row.get("Classification")),
                "soft404": _text(row.get("Soft404 Filtered")),
                "marcador": _display_es(row.get("Sensitive Marker")),
                "evidencia": _display_es(row.get("Evidence Summary")),
            }
        )

    summary = {
        "targets": len(normalized_targets),
        "waf": sum(1 for row in normalized_targets if row["waf"] or row["wafw00f"] or row["perfil_waf"]),
        "puertos": sum(len(row["puertos"]) for row in normalized_targets),
        "rutas": len(normalized_hits),
        "tecnologias": sum(len(row["tecnologias"]) + len(row["whatweb"]) for row in normalized_targets),
    }
    return {"available": True, "targets": normalized_targets, "hits": normalized_hits[:1000], "summary": summary}


def _brief_error(value: Any) -> str:
    message = " ".join(_text(value).split())
    if not message:
        return "Ejecución degradada; revisar runtime JSON."
    if "Traceback" in message or "urllib3" in message or "ssl" in message.lower() and len(message) > 220:
        return "Error de conexión o validación TLS; revisar runtime JSON."
    return message[:220] + ("…" if len(message) > 220 else "")


def construir_modelo(df: pd.DataFrame) -> dict[str, Any]:
    generated_at = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    cutoff_timestamp = _timestamp_text(df["Timestamp"].max()) if not df.empty else ""
    cutoff = cutoff_timestamp[:10] or dt.date.today().isoformat()
    latest_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    if not df.empty:
        latest_df = df.sort_values("Timestamp").drop_duplicates(["Asset", "Vuln_ID"], keep="last")
        latest_by_key = {(_text(row.get("Asset")), _text(row.get("Vuln_ID"))): row for row in latest_df.to_dict("records")}
    state_records = cargar_estado_hallazgos()
    if state_records is None:
        rows, state_source = (_fallback_rows(df, cutoff) if not df.empty else []), "FALLBACK_REPORTS"
    else:
        rows, state_source = [], "SCAN_TITAN_STATE"
        for record in state_records.values():
            if not isinstance(record, dict) or not _text(record.get("canonical_id")):
                continue
            key = (_text(record.get("asset") or record.get("target")), _text(record.get("canonical_id")))
            row = _record_from_state(record, latest_by_key.get(key, {}), cutoff)
            exclusion = finding_quality_exclusion(record)
            if exclusion:
                row.update(state='PENDING', status='PENDING', quality='CANDIDATE')
            elif injection_family(record):
                row['quality'] = 'VALIDATED'
            else:
                row['quality'] = 'OBSERVED'
            rows.append(row)
    decisions = load_decisions()
    for row in rows:
        if not row.get('triage_key'):
            row['triage_key'] = triage_key(row)
        row['analyst_discarded'] = decisions.get(row['triage_key'], {}).get('decision') == 'discarded'
    default_criticality, asset_criticality = _asset_criticality_config()
    criticality_factors = {"bajo": .90, "low": .90, "medio": 1.0, "medium": 1.0, "alto": 1.10, "high": 1.10, "critico": 1.20, "crítico": 1.20, "critical": 1.20}
    for row in rows:
        label = asset_criticality.get(row["target"], asset_criticality.get(row["asset"], default_criticality))
        row["asset_criticality"] = label
        row["asset_criticality_factor"] = criticality_factors.get(label.lower(), 1.0)
        row["risk"] = _risk_score(row)
    rows.sort(key=lambda row: (SEVERITY_RANK.get(row["severity"], 99), -row["risk"], row["target"], row["title"]))
    active, not_seen = [row for row in rows if row["state"] == "ACTIVE" and not row["analyst_discarded"]], [row for row in rows if row["state"] == "NOT_SEEN" and not row["analyst_discarded"]]
    new_rows, regressions = [row for row in active if row["status"] == "NEW"], [row for row in active if row["status"] == "REGRESSION"]
    newly_not_seen = [row for row in not_seen if row["state_changed_at"][:10] == cutoff]
    exact_delta = bool(state_records is not None and any(row["state_changed_at"] for row in rows))
    severity_counts, confidence_counts = Counter(row["severity"] for row in active), Counter(row["confidence"] or "unknown" for row in active)
    quality_counts = Counter(row["quality"] for row in active)
    history: list[dict[str, Any]] = []
    if not df.empty:
        grouped = df.groupby([df["Fecha"].dt.strftime("%Y-%m-%d"), "Severidad"]).size().reset_index(name="count")
        by_date: dict[str, dict[str, int]] = defaultdict(lambda: {severity: 0 for severity in SEVERITY_ORDER})
        for item in grouped.to_dict("records"):
            by_date[_text(item["Fecha"])][_text(item["Severidad"]).upper()] = _int(item["count"])
        history = [{"date": date, **counts, "total": sum(counts.values())} for date, counts in sorted(by_date.items())]
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in active:
        by_target[row["target"]].append(row)
    assets = []
    for target, target_rows in by_target.items():
        scores = sorted((row["risk"] for row in target_rows), reverse=True)
        combined = min(100.0, scores[0] + .05 * sum(scores[1:]))
        assets.append({"target": target, "risk": round(combined, 1), "total": len(target_rows), "severity": dict(Counter(r["severity"] for r in target_rows))})
    assets.sort(key=lambda item: (-item["risk"], -item["total"], item["target"]))
    runtime, tool_health = cargar_runtime(), _tool_health(cargar_runtime())
    recon = cargar_recon_modelo()
    runtime_status, runtime_phase, runtime_percent = _text(runtime.get("status") or "unknown").lower(), _text(runtime.get("current_phase")), round(_float(runtime.get("global_percent")), 2)
    complete = runtime_status == "finished" or (runtime_phase == "dashboard" and runtime_percent >= 99.9)
    snapshot_status = "PROVISIONAL" if runtime and not complete else ("FINAL" if runtime else "HISTORICAL_FALLBACK")
    scanner_values = [_text(value) for value in df.get("Scanner", pd.Series(dtype=str)).tolist() if _text(value)]
    scanner = Counter(scanner_values).most_common(1)[0][0] if scanner_values else SCANNER_FALLBACK
    high_critical = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)
    attention = confidence_counts.get("medium", 0) + confidence_counts.get("low", 0) + confidence_counts.get("unknown", 0)
    top_asset = assets[0]["target"] if assets else "N/D"
    summary = (f"El corte contiene {len(active)} hallazgos activos en {len(assets)} activos. {high_critical} requieren prioridad alta o crítica; "
               f"{len(new_rows)} son nuevos y {len(regressions)} corresponden a regresiones registradas. {attention} requieren atención adicional "
               f"por confianza no alta. El activo con mayor exposición combinada es {top_asset}.")
    return {"meta": {"dashboard_version": DASHBOARD_VERSION, "scanner": scanner, "generated_at": generated_at, "cutoff": cutoff_timestamp,
                     "snapshot_status": snapshot_status, "state_source": state_source, "active": len(active), "all_records": len(rows),
                     "not_seen": len(not_seen), "new": len(new_rows), "regressions": len(regressions),
                     "newly_not_seen": len(newly_not_seen) if exact_delta else None,
                     "change_net": len(new_rows) + len(regressions) - len(newly_not_seen) if exact_delta else None,
                     "exact_delta": exact_delta, "high_critical": high_critical, "targets": len(assets),
                     "severity": {severity: severity_counts.get(severity, 0) for severity in SEVERITY_ORDER},
                     "confidence": dict(confidence_counts), "quality": dict(quality_counts),
                     "runtime": {"status": runtime_status, "phase": runtime_phase, "percent": runtime_percent,
                                 "targets_completed": _int(runtime.get("targets_completed")), "target_total": _int(runtime.get("target_total")),
                                 "updated_at": _text(runtime.get("updated_at")), "warning": _brief_error(runtime.get("last_warning")), "error": _brief_error(runtime.get("last_error")) if runtime.get("last_error") else ""},
                     "tools": tool_health, "summary": summary,
                     "risk_formula": "CVSS × confianza × fuerza de evidencia × riesgo de falso positivo × exposición × recurrencia × criticidad del activo"},
            "rows": rows, "history": history, "assets": assets,
            "active_snapshot": [{"date": cutoff, "total": len(active),
                                 **{s: severity_counts.get(s, 0) for s in SEVERITY_ORDER}}],
            "recon": recon,
            "triage": load_decisions(),
            "timeline": build_timeline(Path(CARPETA_REPORTES)),
            "logo": logo_data_uri(BASE_DIR),
            "intelligence": intelligence_model(Path(CARPETA_REPORTES)),
            "priority": sorted(active, key=lambda row: (-row["risk"], SEVERITY_RANK.get(row["severity"], 99)))[:8]}


def generar_executive_summary(df_snapshot: pd.DataFrame, *_: Any) -> str:
    return _text(construir_modelo(df_snapshot).get("meta", {}).get("summary"))


def generar_dashboard(df: pd.DataFrame) -> None:
    if df.empty and cargar_estado_hallazgos() is None:
        print("[-] No hay datos para generar el reporte.")
        return
    model = construir_modelo(df)
    output = Path(ARCHIVO_SALIDA)
    output.parent.mkdir(parents=True, exist_ok=True)
    page = render_daily(_json_for_html(model))
    temporary = output.with_suffix('.tmp.html')
    temporary.write_text(page, encoding="utf-8")
    temporary.replace(output)
    print(f"[+] DASHBOARD v{DASHBOARD_VERSION} GENERADO: {output.resolve()} | activos={model['meta']['active']} historicos={model['meta']['not_seen']}")


def main() -> int:
    generar_dashboard(obtener_dataframe())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
