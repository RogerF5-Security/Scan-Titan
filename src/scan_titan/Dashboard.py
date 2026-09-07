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


DASHBOARD_VERSION = "21.3.0-community"
SCANNER_FALLBACK = "TITAN v21.2.0 COMMUNITY ZERO-TOUCH"
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
    "Console_Artifact", "Browser_Artifact", "Affected_Locations",
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
    candidate = "potential cve" in title.lower() or "inferred from service version" in title.lower() or fp_risk == "high"
    row: dict[str, Any] = {
        "id": _text(record.get("canonical_id") or latest.get("Vuln_ID")), "fingerprint": _text(record.get("fingerprint")),
        "target": _text(record.get("target") or latest.get("Target")), "asset": _text(record.get("asset") or latest.get("Asset")),
        "severity": severity, "status": status, "state": state,
        "quality": "INFORMATIONAL" if severity == "INFO" else ("CANDIDATE" if candidate else "VALIDATED"),
        "title": title, "category": category_label_es(record.get("category") or latest.get("Categoria") or "Desconocida"),
        "url": _text(record.get("last_url") or latest.get("URL")), "endpoint": _text(latest.get("Endpoint")),
        "param": _text(latest.get("Param")), "method": _text(latest.get("Method")), "payload": _text(latest.get("Payload")),
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
    return row


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
                     "console_artifact": item.get("Console_Artifact"), "browser_artifact": item.get("Browser_Artifact")}
        rows.append(_record_from_state(synthetic, item, cutoff))
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
            rows.append(_record_from_state(record, latest_by_key.get(key, {}), cutoff))
    default_criticality, asset_criticality = _asset_criticality_config()
    criticality_factors = {"bajo": .90, "low": .90, "medio": 1.0, "medium": 1.0, "alto": 1.10, "high": 1.10, "critico": 1.20, "crítico": 1.20, "critical": 1.20}
    for row in rows:
        label = asset_criticality.get(row["target"], asset_criticality.get(row["asset"], default_criticality))
        row["asset_criticality"] = label
        row["asset_criticality_factor"] = criticality_factors.get(label.lower(), 1.0)
        row["risk"] = _risk_score(row)
    rows.sort(key=lambda row: (SEVERITY_RANK.get(row["severity"], 99), -row["risk"], row["target"], row["title"]))
    active, not_seen = [row for row in rows if row["state"] == "ACTIVE"], [row for row in rows if row["state"] == "NOT_SEEN"]
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
            "recon": recon,
            "priority": sorted(active, key=lambda row: (-row["risk"], SEVERITY_RANK.get(row["severity"], 99)))[:8]}


HTML_TEMPLATE = r'''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'self' data:;img-src 'self' data:;style-src 'unsafe-inline';script-src 'unsafe-inline';connect-src 'none';object-src 'none';base-uri 'none'"><title>Scan Titan — Centro de Vulnerabilidades</title>
<style>
:root{--bg:#07101d;--panel:#0d1929;--panel2:#111f31;--line:#243750;--text:#edf4ff;--muted:#91a4bd;--blue:#3ba7ff;--cyan:#46d7d0;--red:#ff5c73;--orange:#ffad42;--yellow:#f4d35e;--green:#3fd18b;--gray:#708198;--shadow:0 14px 36px rgba(0,0,0,.22)}*{box-sizing:border-box}html,body{margin:0;max-width:100%;overflow-x:hidden}body{min-height:100vh;background:radial-gradient(circle at 85% -10%,#12335a 0,transparent 32%),var(--bg);color:var(--text);font:14px/1.5 Inter,Segoe UI,Arial,sans-serif}button,input,select{font:inherit}.shell{width:min(1540px,100%);margin:auto;padding:0 28px 42px}.topbar{border-bottom:1px solid var(--line);background:rgba(7,16,29,.94);position:sticky;top:0;z-index:20;backdrop-filter:blur(16px)}.topbar-inner{width:min(1540px,100%);margin:auto;padding:16px 28px;display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:13px;min-width:0}.brand-mark{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(145deg,var(--blue),#2253d1);font-weight:800;box-shadow:0 0 28px rgba(59,167,255,.28)}.brand h1{font-size:18px;margin:0}.brand p{margin:1px 0 0;color:var(--muted);font-size:12px}.top-actions{display:flex;gap:8px}.btn{border:1px solid var(--line);background:#122239;color:var(--text);border-radius:9px;padding:9px 13px;cursor:pointer}.btn:hover{border-color:var(--blue);background:#17304d}.btn.primary{background:var(--blue);border-color:var(--blue);color:#03101d;font-weight:700}.btn.ghost{background:transparent}.btn.small{padding:6px 9px;font-size:12px}.hero{padding:28px 0 18px;display:grid;grid-template-columns:minmax(0,1.45fr) minmax(300px,.55fr);gap:18px}.panel{background:linear-gradient(145deg,rgba(17,31,49,.96),rgba(10,23,39,.96));border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow)}.hero-main{padding:24px}.eyebrow{color:var(--blue);font-size:11px;font-weight:800;letter-spacing:1.4px;text-transform:uppercase}.hero h2{font-size:28px;line-height:1.2;margin:8px 0 10px}.summary{color:#c6d4e6;max-width:900px;margin:0}.meta-line{display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:18px;color:var(--muted);font-size:12px}.snapshot{padding:20px;display:flex;flex-direction:column;justify-content:center}.status-line{display:flex;align-items:center;gap:9px;font-weight:800}.dot{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 14px currentColor}.status-PROVISIONAL .dot{background:var(--orange)}.status-HISTORICAL_FALLBACK .dot{background:var(--gray)}.snapshot dl{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:15px 0 0}.snapshot dt{color:var(--muted)}.snapshot dd{margin:0;text-align:right;overflow-wrap:anywhere}.alert{display:none;margin:0 0 18px;padding:13px 15px;border:1px solid rgba(255,173,66,.5);background:rgba(255,173,66,.08);border-radius:11px;color:#ffd8a2}.alert.show{display:block}.kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin-bottom:18px}.kpi{padding:17px;min-width:0}.kpi-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px}.kpi-value{font-size:30px;font-weight:800;margin-top:6px}.kpi-note{font-size:11px;color:var(--muted)}.tone-red{color:var(--red)}.tone-blue{color:var(--blue)}.tone-green{color:var(--green)}.tone-orange{color:var(--orange)}.grid-2{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(320px,.65fr);gap:18px;margin-bottom:18px}.panel-head{padding:17px 19px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:12px}.panel-head h3{font-size:14px;margin:0}.panel-body{padding:18px}.history-bars{height:245px;display:flex;align-items:flex-end;gap:13px;border-bottom:1px solid var(--line);padding:12px 8px 0;overflow-x:auto}.history-col{height:100%;min-width:56px;display:flex;flex-direction:column;justify-content:flex-end;align-items:center}.bar-total{font-size:10px;color:var(--muted);margin-bottom:5px}.bar-stack{width:30px;display:flex;flex-direction:column-reverse;border-radius:5px 5px 0 0;overflow:hidden;min-height:2px;background:#1a2a40}.bar-segment{width:100%;min-height:1px}.bar-label{font-size:10px;color:var(--muted);padding:8px 0}.legend{display:flex;flex-wrap:wrap;gap:13px;margin-top:14px;color:var(--muted);font-size:11px}.legend i{width:8px;height:8px;border-radius:2px;display:inline-block;margin-right:5px}.sev-CRITICAL{--sev:var(--red)}.sev-HIGH{--sev:#ff7d55}.sev-MEDIUM{--sev:var(--orange)}.sev-LOW{--sev:var(--yellow)}.sev-INFO{--sev:var(--blue)}.bar-segment.sev-CRITICAL,.legend .sev-CRITICAL{background:var(--red)}.bar-segment.sev-HIGH,.legend .sev-HIGH{background:#ff7d55}.bar-segment.sev-MEDIUM,.legend .sev-MEDIUM{background:var(--orange)}.bar-segment.sev-LOW,.legend .sev-LOW{background:var(--yellow)}.bar-segment.sev-INFO,.legend .sev-INFO{background:var(--blue)}.asset-list{display:grid;gap:13px}.asset-row{display:grid;grid-template-columns:minmax(130px,1fr) 2fr 48px;gap:10px;align-items:center}.asset-name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.risk-track{height:8px;border-radius:10px;background:#1b2b41;overflow:hidden}.risk-fill{height:100%;background:linear-gradient(90deg,var(--cyan),var(--orange),var(--red));border-radius:10px}.risk-value{text-align:right;font-weight:700}.queue{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.queue-item{padding:14px;border:1px solid var(--line);border-radius:11px;background:#0a1727;min-width:0}.queue-top{display:flex;justify-content:space-between}.queue-title{font-weight:700;margin:9px 0 7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.queue-meta{color:var(--muted);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.badge{display:inline-flex;border-radius:999px;border:1px solid currentColor;padding:3px 7px;font-size:10px;font-weight:800;white-space:nowrap}.badge.severity{color:var(--sev)}.status-NEW{color:var(--green)}.status-RECURRING{color:var(--blue)}.status-REGRESSION{color:var(--red)}.status-NOT_SEEN{color:var(--gray)}.operations{margin-bottom:18px}.ops-grid{display:grid;grid-template-columns:1.1fr .9fr;gap:18px}.health-row{display:flex;flex-wrap:wrap;gap:9px}.health-chip{padding:7px 10px;border:1px solid var(--line);border-radius:8px;color:var(--muted)}.health-chip strong{color:var(--text)}.warning-list{margin:12px 0 0;padding-left:20px;color:#ffd8a2}.formula{font-size:12px;color:var(--muted);margin-top:12px}.table-panel{overflow:hidden}.toolbar{padding:15px 18px;border-bottom:1px solid var(--line);display:grid;grid-template-columns:minmax(220px,1.3fr) repeat(4,minmax(130px,.55fr)) auto;gap:9px}.control{width:100%;background:#091522;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 10px}.view-tabs{display:flex;gap:7px;padding:13px 18px;border-bottom:1px solid var(--line);overflow:auto}.tab{border:1px solid var(--line);background:transparent;color:var(--muted);border-radius:999px;padding:7px 11px;cursor:pointer;white-space:nowrap}.tab.active{background:rgba(59,167,255,.13);border-color:var(--blue);color:var(--text)}.table-wrap{width:100%;max-width:100%;overflow-x:auto}.findings-table{width:100%;min-width:1160px;border-collapse:collapse}.findings-table th{font-size:10px;letter-spacing:.7px;text-transform:uppercase;color:var(--muted);text-align:left;padding:11px 12px;background:#091522;border-bottom:1px solid var(--line);cursor:pointer}.findings-table td{padding:12px;border-bottom:1px solid rgba(36,55,80,.65)}.findings-table tbody tr:hover{background:rgba(59,167,255,.055)}.target-cell,.title-cell{max-width:250px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.risk-number{font-weight:800}.table-foot{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 18px;color:var(--muted)}.pager{display:flex;gap:7px;align-items:center}.empty{padding:38px;text-align:center;color:var(--muted)}dialog{width:min(920px,calc(100% - 28px));max-height:90vh;padding:0;border:1px solid var(--line);border-radius:16px;background:var(--panel);color:var(--text);box-shadow:0 28px 80px rgba(0,0,0,.55)}dialog::backdrop{background:rgba(2,8,16,.78)}.dialog-head{position:sticky;top:0;z-index:2;background:var(--panel);border-bottom:1px solid var(--line);padding:18px 20px;display:flex;justify-content:space-between;gap:18px}.dialog-head h2{font-size:19px;margin:4px 0}.icon-btn{border:0;background:#1a2b42;color:var(--text);width:34px;height:34px;border-radius:9px;cursor:pointer}.dialog-body{padding:20px}.detail-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:11px;margin-bottom:18px}.detail-card{background:#091522;border:1px solid var(--line);border-radius:10px;padding:11px;min-width:0}.detail-card span{display:block;color:var(--muted);font-size:10px;text-transform:uppercase}.detail-card strong{display:block;margin-top:4px;overflow-wrap:anywhere}.detail-section{margin:18px 0}.detail-section h4{font-size:11px;color:var(--blue);text-transform:uppercase;margin:0 0 7px}.detail-content{background:#091522;border:1px solid var(--line);border-radius:10px;padding:12px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:230px;overflow:auto}.detail-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.toast{position:fixed;right:22px;bottom:22px;z-index:100;background:#15314a;border:1px solid var(--blue);border-radius:10px;padding:11px 14px;opacity:0;transform:translateY(12px);pointer-events:none;transition:.2s}.toast.show{opacity:1;transform:none}.muted{color:var(--muted)}
@media(max-width:1180px){.kpis{grid-template-columns:repeat(3,1fr)}.queue{grid-template-columns:repeat(2,1fr)}.toolbar{grid-template-columns:repeat(3,1fr)}.toolbar .search{grid-column:span 2}.ops-grid{grid-template-columns:1fr}}@media(max-width:780px){.shell{padding:0 14px 30px}.topbar-inner{padding:12px 14px}.brand p,.top-actions .optional{display:none}.hero{grid-template-columns:1fr}.hero h2{font-size:23px}.kpis{grid-template-columns:repeat(2,1fr)}.grid-2{grid-template-columns:1fr}.queue{grid-template-columns:1fr}.toolbar{grid-template-columns:1fr 1fr}.toolbar .search{grid-column:1/-1}.detail-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:480px){.toolbar{grid-template-columns:1fr}.toolbar .search{grid-column:auto}.detail-grid{grid-template-columns:1fr}.kpi-value{font-size:25px}}@media print{body{background:#fff;color:#111}.topbar,.toolbar,.view-tabs,.top-actions,.btn,.pager{display:none!important}.shell{width:100%;padding:0}.panel{box-shadow:none;border:1px solid #bbb;background:#fff}.findings-table{min-width:0;font-size:10px}}
</style><style>.recon-toolbar{padding:15px 18px;border-bottom:1px solid var(--line)}.recon-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.recon-card{background:#091522;border:1px solid var(--line);border-radius:12px;padding:14px;min-width:0}.recon-card h4{margin:0 0 6px;font-size:15px}.recon-meta{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:10px}.recon-section{margin-top:10px}.recon-section strong{display:block;color:var(--blue);font-size:11px;text-transform:uppercase;margin-bottom:5px}.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{display:inline-flex;align-items:center;max-width:520px;padding:4px 7px;border:1px solid #31516f;background:#10243a;color:#d8ecff;border-radius:7px;line-height:1.25;overflow-wrap:anywhere}.hit-table{width:100%;min-width:980px;border-collapse:collapse}.hit-table th{font-size:10px;letter-spacing:.7px;text-transform:uppercase;color:var(--muted);text-align:left;padding:10px;background:#091522;border-bottom:1px solid var(--line)}.hit-table td{padding:10px;border-bottom:1px solid rgba(36,55,80,.65);vertical-align:top}.status-200{color:var(--green)}.status-301,.status-302{color:var(--blue)}.status-403{color:var(--yellow)}.status-500{color:var(--red)}@media(max-width:980px){.recon-grid{grid-template-columns:1fr}}</style></head><body><header class="topbar"><div class="topbar-inner"><div class="brand"><div class="brand-mark">ST</div><div><h1>Scan Titan</h1><p>Centro operativo de vulnerabilidades</p></div></div><div class="top-actions"><button class="btn ghost optional" id="printBtn">Imprimir</button><button class="btn primary" id="exportBtn">Exportar CSV</button></div></div></header><main class="shell">
<section class="hero"><article class="panel hero-main"><div class="eyebrow">Resumen ejecutivo verificable</div><h2>Postura de vulnerabilidades</h2><p class="summary" id="summary"></p><div class="meta-line"><span id="scanner"></span><span id="cutoff"></span><span id="generated"></span></div></article><aside class="panel snapshot" id="snapshotCard"><div class="status-line"><span class="dot"></span><span id="snapshotStatus"></span></div><dl><dt>Fuente</dt><dd id="stateSource"></dd><dt>Runtime</dt><dd id="runtimeStatus"></dd><dt>Cobertura</dt><dd id="coverage"></dd><dt>Versión</dt><dd id="version"></dd></dl></aside></section><div class="alert" id="runtimeAlert"></div><section class="kpis" id="kpis"></section>
<section class="grid-2"><article class="panel"><header class="panel-head"><h3>Hallazgos observados por ejecución</h3><span class="muted">Observaciones únicas por día</span></header><div class="panel-body"><div class="history-bars" id="history"></div><div class="legend" id="legend"></div></div></article><article class="panel"><header class="panel-head"><h3>Exposición por activo</h3><span class="muted">Riesgo combinado 0–100</span></header><div class="panel-body"><div class="asset-list" id="assets"></div><div class="formula" id="riskFormula"></div></div></article></section>
<section class="panel operations"><header class="panel-head"><h3>Cola priorizada de validación y remediación</h3><span class="muted">Mayor riesgo verificable primero</span></header><div class="panel-body"><div class="queue" id="priority"></div></div></section>
<section class="panel operations"><header class="panel-head"><h3>Salud del escaneo</h3><span class="muted">Cobertura, degradaciones y trazabilidad</span></header><div class="panel-body ops-grid"><div><div class="health-row" id="toolHealth"></div><ul class="warning-list" id="toolWarnings"></ul></div><div><div class="detail-content" id="runtimeDetail"></div><div class="detail-actions"><a class="btn small" href="Recon_Dashboard.html">Abrir Recon Dashboard</a><a class="btn small" href="Recon_Sitemap.html">Abrir Site Map</a><a class="btn small" href="scan_titan_runtime.json">Abrir runtime JSON</a></div></div></div></section>
<section class="panel operations"><header class="panel-head"><h3>Reconocimiento por target</h3><span class="muted" id="reconScope">Inventario separado de vulnerabilidades</span></header><div class="view-tabs" id="reconTabs"><button class="tab active" data-recon-view="targets">Superficie</button><button class="tab" data-recon-view="hits">Rutas Wordlist</button></div><div class="recon-toolbar"><input class="control search" id="reconSearch" type="search" placeholder="Buscar target, IP, tecnología, ruta, WAF o header…"></div><div class="panel-body" id="reconBody"></div></section>
<section class="panel table-panel"><header class="panel-head"><h3>Registro operativo de hallazgos</h3><span class="muted" id="tableScope"></span></header><div class="view-tabs" id="viewTabs"><button class="tab active" data-view="ACTIVE">Activos</button><button class="tab" data-view="NEW">Nuevos</button><button class="tab" data-view="REGRESSION">Regresiones</button><button class="tab" data-view="RETEST">Cola de retest</button><button class="tab" data-view="NOT_SEEN">No vistos</button><button class="tab" data-view="ALL">Todos</button></div><div class="toolbar"><input class="control search" id="search" type="search" placeholder="Buscar ID, activo, título, URL o evidencia…"><select class="control" id="severityFilter"><option value="">Toda severidad</option></select><select class="control" id="targetFilter"><option value="">Todo activo</option></select><select class="control" id="confidenceFilter"><option value="">Toda confianza</option></select><select class="control" id="sourceFilter"><option value="">Toda fuente</option></select><button class="btn" id="clearFilters">Limpiar</button></div><div class="table-wrap"><table class="findings-table"><thead><tr><th data-sort="risk">Riesgo</th><th data-sort="target">Activo</th><th data-sort="severity">Severidad</th><th data-sort="status">Estado</th><th data-sort="last_seen">Última vez</th><th data-sort="title">Hallazgo</th><th data-sort="confidence">Confianza</th><th data-sort="sources">Fuente</th><th>Acción</th></tr></thead><tbody id="findingRows"></tbody></table></div><div class="table-foot"><span id="rowCount"></span><div class="pager"><button class="btn small" id="prevPage">Anterior</button><span id="pageInfo"></span><button class="btn small" id="nextPage">Siguiente</button></div></div></section></main>
<dialog id="detailDialog"><div class="dialog-head"><div><div class="eyebrow" id="detailId"></div><h2 id="detailTitle"></h2></div><button class="icon-btn" id="closeDialog">×</button></div><div class="dialog-body" id="detailBody"></div></dialog><div class="toast" id="toast"></div><script type="application/json" id="dashboardData">__DASHBOARD_DATA__</script>
<script>(()=>{'use strict';const data=JSON.parse(document.getElementById('dashboardData').textContent),meta=data.meta,severityRank={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4},state={view:'ACTIVE',query:'',severity:'',target:'',confidence:'',source:'',sort:'risk',direction:-1,page:1,pageSize:25,filtered:[],retest:new Set()},$=id=>document.getElementById(id),esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),statusLabel=v=>({NEW:'NUEVO',RECURRING:'RECURRENTE',REGRESSION:'REGRESIÓN',NOT_SEEN:'NO VISTO'}[v]||v),severityLabel=v=>({CRITICAL:'CRÍTICA',HIGH:'ALTA',MEDIUM:'MEDIA',LOW:'BAJA',INFO:'INFO'}[v]||v),fmt=v=>v?v.replace('T',' ').slice(0,19):'N/D',badge=(t,c)=>`<span class="badge ${c}">${esc(t)}</span>`;let toastTimer;try{state.retest=new Set(JSON.parse(localStorage.getItem('scanTitanRetestQueueV20.2')||'[]'))}catch(_){}function toast(m){const n=$('toast');n.textContent=m;n.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>n.classList.remove('show'),1800)}async function copyText(t){try{await navigator.clipboard.writeText(t)}catch(_){const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove()}toast('Copiado al portapapeles')}const retestKey=(id,asset)=>`${asset}|${id}`;function toggleRetest(id,asset){const key=retestKey(id,asset);if(state.retest.has(key)){state.retest.delete(key);toast('Retirado de la cola de retest')}else{state.retest.add(key);toast('Agregado a la cola de retest')}try{localStorage.setItem('scanTitanRetestQueueV20.2',JSON.stringify([...state.retest]))}catch(_){}render()}
$('summary').textContent=meta.summary;$('scanner').textContent=`Scanner: ${meta.scanner}`;$('cutoff').textContent=`Corte: ${fmt(meta.cutoff)}`;$('generated').textContent=`Generado: ${fmt(meta.generated_at)}`;$('snapshotStatus').textContent=({FINAL:'SNAPSHOT FINAL',PROVISIONAL:'SNAPSHOT PROVISIONAL',HISTORICAL_FALLBACK:'FALLBACK HISTÓRICO'}[meta.snapshot_status]||meta.snapshot_status);$('snapshotCard').classList.add(`status-${meta.snapshot_status}`);$('stateSource').textContent=meta.state_source;$('runtimeStatus').textContent=`${meta.runtime.status||'unknown'} · ${meta.runtime.phase||'sin fase'}`;$('coverage').textContent=meta.runtime.target_total?`${meta.runtime.targets_completed}/${meta.runtime.target_total} targets · ${meta.runtime.percent}%`:'N/D';$('version').textContent=`Dashboard ${meta.dashboard_version}`;if(meta.snapshot_status==='PROVISIONAL'||meta.runtime.warning||meta.runtime.error){const p=[];if(meta.snapshot_status==='PROVISIONAL')p.push('El escaneo no había finalizado al generar este corte.');if(meta.runtime.warning)p.push(`Advertencia: ${meta.runtime.warning}`);if(meta.runtime.error)p.push(`Error: ${meta.runtime.error}`);$('runtimeAlert').textContent=p.join(' ');$('runtimeAlert').classList.add('show')}
const delta=meta.exact_delta?(meta.change_net>0?`+${meta.change_net}`:String(meta.change_net)):'N/D',kpis=[['Hallazgos activos',meta.active,'Vigentes en el estado actual','tone-blue'],['Alta / crítica',meta.high_critical,'Prioridad inmediata','tone-red'],['Nuevos',meta.new,'Primer hallazgo en este corte','tone-green'],['Regresiones',meta.regressions,'Reaparecieron tras no verse','tone-red'],['No vistos',meta.not_seen,'Histórico conservado','tone-orange'],['Cambio neto',delta,meta.exact_delta?'Nuevos + regresiones − no vistos':'Disponible desde transición v20.2','tone-blue']];$('kpis').innerHTML=kpis.map(k=>`<article class="panel kpi"><div class="kpi-label">${esc(k[0])}</div><div class="kpi-value ${k[3]}">${esc(k[1])}</div><div class="kpi-note">${esc(k[2])}</div></article>`).join('');
const maxH=Math.max(1,...data.history.map(i=>i.total));$('history').innerHTML=data.history.length?data.history.map(i=>{const totalH=Math.max(3,i.total/maxH*190),segments=['INFO','LOW','MEDIUM','HIGH','CRITICAL'].map(s=>`<span class="bar-segment sev-${s}" style="height:${i.total?i[s]/i.total*totalH:0}px" title="${severityLabel(s)}: ${i[s]}"></span>`).join('');return `<div class="history-col"><span class="bar-total">${i.total}</span><div class="bar-stack" style="height:${totalH}px">${segments}</div><span class="bar-label">${esc(i.date.slice(5))}</span></div>`}).join(''):'<div class="empty">Sin histórico disponible</div>';$('legend').innerHTML=['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s=>`<span><i class="sev-${s}"></i>${severityLabel(s)}: ${meta.severity[s]||0}</span>`).join('');$('assets').innerHTML=data.assets.length?data.assets.slice(0,10).map(i=>`<div class="asset-row"><span class="asset-name" title="${esc(i.target)}">${esc(i.target)}</span><div class="risk-track"><div class="risk-fill" style="width:${i.risk}%"></div></div><span class="risk-value">${i.risk}</span></div>`).join(''):'<div class="empty">Sin activos vulnerables</div>';$('riskFormula').textContent=`Fórmula: ${meta.risk_formula}. La exposición combina la probabilidad de al menos un hallazgo material.`;
$('priority').innerHTML=data.priority.length?data.priority.map(r=>`<article class="queue-item"><div class="queue-top">${badge(severityLabel(r.severity),`severity sev-${r.severity}`)}<strong>${r.risk}</strong></div><div class="queue-title" title="${esc(r.title)}">${esc(r.title)}</div><div class="queue-meta">${esc(r.target)} · ${statusLabel(r.status)} · ${esc(r.confidence)}</div><button class="btn small" data-inspect="${esc(r.id)}" data-asset="${esc(r.asset)}" style="margin-top:10px">Revisar</button></article>`).join(''):'<div class="empty">No hay hallazgos activos</div>';const health=meta.tools.counts||{};$('toolHealth').innerHTML=Object.keys(health).length?Object.entries(health).map(([k,v])=>`<span class="health-chip"><strong>${v}</strong> ${esc(k)}</span>`).join(''):'<span class="muted">Sin telemetría externa disponible</span>';$('toolWarnings').innerHTML=(meta.tools.degraded||[]).map(i=>`<li><strong>${esc(i.tool)} ${esc(i.profile)}</strong> · ${esc(i.target)} — ${esc(i.error||i.status)}</li>`).join('');$('runtimeDetail').textContent=[`Estado: ${meta.runtime.status||'N/D'}`,`Fase: ${meta.runtime.phase||'N/D'}`,`Progreso: ${meta.runtime.percent}%`,`Targets: ${meta.runtime.targets_completed}/${meta.runtime.target_total}`,`Actualizado: ${meta.runtime.updated_at||'N/D'}`].join('\n');
let reconView='targets',reconQuery='';const recon=data.recon||{};function arr(v){return Array.isArray(v)?v:(v?[String(v)]:[])}function chips(v,max=18){const items=arr(v).filter(Boolean);return items.length?`<div class="chips">${items.slice(0,max).map(x=>`<span class="chip">${esc(x)}</span>`).join('')}${items.length>max?`<span class="chip muted">+${items.length-max} mas</span>`:''}</div>`:'<span class="muted">N/D</span>'}function reconMatch(row){const q=reconQuery.toLowerCase();return !q||JSON.stringify(row).toLowerCase().includes(q)}function reconSection(label,value,max){return `<div class="recon-section"><strong>${esc(label)}</strong>${chips(value,max)}</div>`}function renderRecon(){const body=$('reconBody');if(!body)return;if(!recon.available){body.innerHTML='<div class="empty">Recon Matrix aun no esta disponible. Ejecuta un escaneo para poblarla.</div>';$('reconScope').textContent='Sin matriz de reconocimiento';return}if(reconView==='hits'){const rows=(recon.hits||[]).filter(reconMatch).slice(0,400);$('reconScope').textContent=`${rows.length} rutas filtradas · ${recon.summary?.rutas||0} rutas registradas`;body.innerHTML=`<div class="table-wrap"><table class="hit-table"><thead><tr><th>Estado</th><th>Target</th><th>Ruta</th><th>Clasificación</th><th>Soft404</th><th>Evidencia</th></tr></thead><tbody>${rows.length?rows.map(h=>`<tr><td class="status-${esc(h.status)}">${esc(h.status||'N/D')}</td><td>${esc(h.target)}</td><td><code>${esc(h.url||h.path)}</code></td><td>${esc(h.clasificacion||'N/D')}</td><td>${esc(h.soft404||'N/D')}</td><td>${esc(h.evidencia||h.marcador||'')}</td></tr>`).join(''):'<tr><td colspan="6"><div class="empty">No hay rutas para el filtro actual.</div></td></tr>'}</tbody></table></div>`;return}const rows=(recon.targets||[]).filter(reconMatch);$('reconScope').textContent=`${rows.length} target(s) visibles · WAF en ${recon.summary?.waf||0} target(s)`;body.innerHTML=rows.length?`<div class="recon-grid">${rows.map(r=>`<article class="recon-card"><h4>${esc(r.target)}</h4><div class="recon-meta">${badge(esc(r.tipo||'Objetivo'),'status-RECURRING')}${r.ip?badge(esc(r.ip),'status-NOT_SEEN'):''}${r.ultima?badge(`Actualizado ${esc(r.ultima.slice(0,19))}`,'status-NEW'):''}</div>${reconSection('URL base',r.url? [r.url]:[],4)}${reconSection('WAF / CDN',arr(r.waf).concat(r.wafw00f?[r.wafw00f]:[],r.perfil_waf?[r.perfil_waf]:[]),10)}${reconSection('Puertos y servicios',arr(r.puertos).concat(arr(r.servicios)),18)}${reconSection('Tecnologías',arr(r.tecnologias).concat(arr(r.whatweb)),24)}${reconSection('Rutas / endpoints',r.rutas,28)}${reconSection('Login y subdominios',arr(r.login).concat(arr(r.subdominios)),20)}${reconSection('Headers y cookies',arr(r.headers).concat(r.cookies?[r.cookies]:[]),18)}${reconSection('Librerías JavaScript',r.js,20)}</article>`).join('')}</div>`:'<div class="empty">No hay objetivos de reconocimiento para el filtro actual.</div>'}renderRecon();
function unique(k){return[...new Set(data.rows.map(r=>r[k]).filter(Boolean))].sort((a,b)=>String(a).localeCompare(String(b)))}function fill(id,vals,label){vals.forEach(v=>$(id).insertAdjacentHTML('beforeend',`<option value="${esc(v)}">${esc(label?label(v):v)}</option>`))}fill('severityFilter',['CRITICAL','HIGH','MEDIUM','LOW','INFO'],severityLabel);fill('targetFilter',unique('target'));fill('confidenceFilter',unique('confidence'));fill('sourceFilter',[...new Set(data.rows.flatMap(r=>String(r.sources||'').split(',').map(v=>v.trim()).filter(Boolean)))].sort());function matchView(r){if(state.view==='ALL')return true;if(state.view==='ACTIVE')return r.state==='ACTIVE';if(state.view==='NOT_SEEN')return r.state==='NOT_SEEN';if(state.view==='RETEST')return state.retest.has(retestKey(r.id,r.asset));return r.status===state.view}function sortVal(r,k){if(k==='severity')return severityRank[r.severity]??99;if(k==='risk')return Number(r.risk)||0;return String(r[k]??'').toLowerCase()}function filtered(){const q=state.query.toLowerCase();return data.rows.filter(r=>matchView(r)&&(!state.severity||r.severity===state.severity)&&(!state.target||r.target===state.target)&&(!state.confidence||r.confidence===state.confidence)&&(!state.source||String(r.sources||'').split(',').map(v=>v.trim()).includes(state.source))&&(!q||[r.id,r.target,r.asset,r.title,r.url,r.evidence,r.sources,r.category].some(v=>String(v||'').toLowerCase().includes(q)))).sort((a,b)=>{const av=sortVal(a,state.sort),bv=sortVal(b,state.sort);return av<bv?-state.direction:av>bv?state.direction:0})}
function render(){state.filtered=filtered();const pages=Math.max(1,Math.ceil(state.filtered.length/state.pageSize));state.page=Math.min(state.page,pages);const visible=state.filtered.slice((state.page-1)*state.pageSize,state.page*state.pageSize);$('findingRows').innerHTML=visible.length?visible.map(r=>`<tr><td><span class="risk-number">${r.risk}</span></td><td class="target-cell" title="${esc(r.target)}">${esc(r.target)}</td><td>${badge(severityLabel(r.severity),`severity sev-${r.severity}`)}</td><td>${badge(statusLabel(r.status),`status-${r.status}`)}</td><td>${esc(r.last_seen.slice(0,10)||'N/D')}</td><td class="title-cell" title="${esc(r.title)}">${esc(r.title)}</td><td>${esc(r.confidence||'N/D')}</td><td class="target-cell" title="${esc(r.sources)}">${esc(r.sources||'N/D')}</td><td><button class="btn small" data-inspect="${esc(r.id)}" data-asset="${esc(r.asset)}">Inspeccionar</button></td></tr>`).join(''):'<tr><td colspan="9"><div class="empty">No hay hallazgos para los filtros seleccionados.</div></td></tr>';$('rowCount').textContent=`${state.filtered.length} hallazgos · mostrando ${visible.length}`;$('tableScope').textContent=`Vista: ${state.view}`;$('pageInfo').textContent=`${state.page} / ${pages}`;$('prevPage').disabled=state.page<=1;$('nextPage').disabled=state.page>=pages}
const field=(l,v)=>`<div class="detail-card"><span>${esc(l)}</span><strong>${esc(v||'N/D')}</strong></div>`,section=(l,v,c)=>!v?'':`<section class="detail-section"><h4>${esc(l)}</h4><div class="detail-content">${esc(v)}</div>${c?`<div class="detail-actions"><button class="btn small" data-copy="${esc(c)}">Copiar</button></div>`:''}</section>`;function openDetail(id,asset){const r=data.rows.find(i=>i.id===id&&i.asset===asset)||data.rows.find(i=>i.id===id);if(!r)return;$('detailId').textContent=`${r.id} · ${r.target}`;$('detailTitle').textContent=r.title;const links=[`<button class="btn small" data-retest="${esc(r.id)}" data-asset="${esc(r.asset)}">${state.retest.has(retestKey(r.id,r.asset))?'Quitar de retest':'Marcar para retest'}</button>`];if(r.evidence_href)links.push(`<a class="btn small" href="${esc(r.evidence_href)}">Abrir evidencia</a>`);if(r.browser_href)links.push(`<a class="btn small" href="${esc(r.browser_href)}">Abrir evidencia browser</a>`);if(r.console_href)links.push(`<a class="btn small" href="${esc(r.console_href)}">Abrir consola</a>`);$('detailBody').innerHTML=`<div class="detail-grid">${field('Severidad',severityLabel(r.severity))}${field('Estado',statusLabel(r.status))}${field('Riesgo',r.risk)}${field('CVSS',r.cvss||'N/D')}${field('Confianza',r.confidence)}${field('Fuerza de evidencia',r.evidence_strength)}${field('Riesgo falso positivo',r.false_positive_risk)}${field('Calidad',r.quality)}${field('CWE',r.cwe)}${field('OWASP',r.owasp)}${field('Primera detección',fmt(r.first_seen))}${field('Última detección',fmt(r.last_seen))}${field('Ocurrencias',r.occurrences)}${field('Regresiones',r.regression_count)}${field('Categoría',r.category)}${field('Fuentes',r.sources)}</div>${section('Ubicación / URL',[r.url,r.endpoint&&`Endpoint: ${r.endpoint}`,r.param&&`Parámetro: ${r.param}`,r.method&&`Método: ${r.method}`].filter(Boolean).join('\n'),r.url)}${section('Ubicaciones afectadas',r.affected_locations)}${section('Evidencia técnica',r.evidence,r.evidence)}${section('Payload / HTTP',[r.payload,r.http].filter(Boolean).join('\n'))}${section('Impacto',r.impact)}${section('Remediación',r.remediation||r.recommendation)}${section('Prueba manual',r.manual_command,r.manual_command)}<div class="detail-actions">${links.join('')}</div>`;$('detailDialog').showModal()}
document.addEventListener('click',e=>{const i=e.target.closest('[data-inspect]');if(i){openDetail(i.dataset.inspect,i.dataset.asset);return}const c=e.target.closest('[data-copy]');if(c){copyText(c.dataset.copy);return}const r=e.target.closest('[data-retest]');if(r){toggleRetest(r.dataset.retest,r.dataset.asset);$('detailDialog').close()}});$('closeDialog').onclick=()=>$('detailDialog').close();$('viewTabs').onclick=e=>{const t=e.target.closest('[data-view]');if(!t)return;document.querySelectorAll('.tab').forEach(n=>n.classList.remove('active'));t.classList.add('active');state.view=t.dataset.view;state.page=1;render()};[['search','input','query'],['severityFilter','change','severity'],['targetFilter','change','target'],['confidenceFilter','change','confidence'],['sourceFilter','change','source']].forEach(([id,ev,key])=>$(id).addEventListener(ev,e=>{state[key]=e.target.value;state.page=1;render()}));document.querySelectorAll('th[data-sort]').forEach(th=>th.onclick=()=>{if(state.sort===th.dataset.sort)state.direction*=-1;else{state.sort=th.dataset.sort;state.direction=th.dataset.sort==='risk'?-1:1}render()});$('clearFilters').onclick=()=>{state.query=state.severity=state.target=state.confidence=state.source='';['search','severityFilter','targetFilter','confidenceFilter','sourceFilter'].forEach(id=>$(id).value='');state.page=1;render()};$('prevPage').onclick=()=>{if(state.page>1){state.page--;render()}};$('nextPage').onclick=()=>{state.page++;render()};$('printBtn').onclick=()=>print();$('exportBtn').onclick=()=>{const headers=['ID','Activo','Target','Severidad','Estado','Riesgo','CVSS','Confianza','Título','Categoría','Fuentes','Primera detección','Última detección','Ocurrencias','URL','Evidencia','Remediación','Prueba manual'],keys=['id','asset','target','severity','status','risk','cvss','confidence','title','category','sources','first_seen','last_seen','occurrences','url','evidence','remediation','manual_command'],csv=[headers,...state.filtered.map(r=>keys.map(k=>r[k]??''))].map(line=>line.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(',')).join('\r\n'),blob=new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`scan_titan_${meta.cutoff.slice(0,10)||'reporte'}.csv`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),500)};render()})();</script></body></html>'''


def generar_executive_summary(df_snapshot: pd.DataFrame, *_: Any) -> str:
    return _text(construir_modelo(df_snapshot).get("meta", {}).get("summary"))


def _patch_dashboard_html(page: str) -> str:
    """Apply compact script fixes to the embedded dashboard template."""
    old = (
        "$('viewTabs').onclick=e=>{const t=e.target.closest('[data-view]');if(!t)return;"
        "document.querySelectorAll('.tab').forEach(n=>n.classList.remove('active'));"
        "t.classList.add('active');state.view=t.dataset.view;state.page=1;render()};"
    )
    new = (
        "$('reconTabs').onclick=e=>{const t=e.target.closest('[data-recon-view]');if(!t)return;"
        "document.querySelectorAll('#reconTabs .tab').forEach(n=>n.classList.remove('active'));"
        "t.classList.add('active');reconView=t.dataset.reconView;renderRecon()};"
        "$('reconSearch').addEventListener('input',e=>{reconQuery=e.target.value;renderRecon()});"
        "$('viewTabs').onclick=e=>{const t=e.target.closest('[data-view]');if(!t)return;"
        "document.querySelectorAll('#viewTabs .tab').forEach(n=>n.classList.remove('active'));"
        "t.classList.add('active');state.view=t.dataset.view;state.page=1;render()};"
    )
    patched = page.replace(old, new) if old in page else page
    replacements = {
        "`Scanner: ${meta.scanner}`": "`Escaner: ${meta.scanner}`",
        "`${meta.runtime.status||'unknown'} · ${meta.runtime.phase||'sin fase'}`":
            "`${({finished:'finalizado',failed:'fallido',timeout:'timeout',running:'en ejecucion',cancelled:'cancelado',interrupted:'interrumpido',no_targets:'sin objetivos'}[meta.runtime.status]||meta.runtime.status||'desconocido')} · ${meta.runtime.phase||'sin fase'}`",
        "`${meta.runtime.targets_completed}/${meta.runtime.target_total} targets · ${meta.runtime.percent}%`":
            "`${meta.runtime.targets_completed}/${meta.runtime.target_total} objetivos · ${meta.runtime.percent}%`",
        "target(s) visibles": "objetivo(s) visibles",
        "target(s)": "objetivo(s)",
        "Reconocimiento por target": "Reconocimiento por objetivo",
        "Rutas Wordlist": "Rutas por wordlist",
        "Buscar target, IP, tecnología, ruta, WAF o header…": "Buscar objetivo, IP, tecnologia, ruta, WAF o header...",
        "`Estado: ${meta.runtime.status||'N/D'}`": "`Estado: ${({finished:'finalizado',failed:'fallido',timeout:'timeout',running:'en ejecucion',cancelled:'cancelado',interrupted:'interrumpido',no_targets:'sin objetivos'}[meta.runtime.status]||meta.runtime.status||'N/D')}`",
        "`Fase: ${meta.runtime.phase||'N/D'}`": "`Fase: ${({module:'modulo',scan:'escaneo',dashboard:'dashboard',cleanup:'limpieza',tool_inventory:'inventario de herramientas',initializing:'inicializacion'}[meta.runtime.phase]||meta.runtime.phase||'N/D')}`",
        "`Targets: ${meta.runtime.targets_completed}/${meta.runtime.target_total}`": "`Objetivos: ${meta.runtime.targets_completed}/${meta.runtime.target_total}`",
        "<th>Target</th>": "<th>Objetivo</th>",
        "const headers=['ID','Activo','Target'": "const headers=['ID','Activo','Objetivo'",
    }
    for source, target in replacements.items():
        patched = patched.replace(source, target)
    recon_css = """
<style id="scan-titan-recon-v2">
.recon-shell{display:grid;gap:16px}
.recon-kpis{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}
.recon-kpi{background:#091522;border:1px solid var(--line);border-radius:10px;padding:12px;min-width:0}
.recon-kpi span{display:block;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.6px}
.recon-kpi strong{display:block;font-size:24px;margin-top:4px}
.recon-layout{display:grid;grid-template-columns:330px minmax(0,1fr);gap:14px;align-items:start}
.recon-list{background:#07111e;border:1px solid var(--line);border-radius:12px;padding:8px;max-height:620px;overflow:auto}
.recon-target{width:100%;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:center;text-align:left;border:1px solid transparent;background:transparent;color:var(--text);border-radius:9px;padding:10px;cursor:pointer}
.recon-target:hover{background:#10243a;border-color:#294766}
.recon-target.active{background:rgba(59,167,255,.16);border-color:var(--blue)}
.recon-target strong{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.recon-target small{display:block;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.recon-target em{font-style:normal;color:var(--cyan);font-size:11px;white-space:nowrap}
.recon-detail{background:#091522;border:1px solid var(--line);border-radius:12px;overflow:hidden}
.recon-detail-head{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;padding:16px 18px;border-bottom:1px solid var(--line);background:linear-gradient(135deg,#10243a,#0b1829)}
.recon-detail-head h4{margin:4px 0 4px;font-size:20px}
.recon-detail-head p{margin:0;color:var(--muted);overflow-wrap:anywhere}
.recon-head-badges{display:flex;flex-wrap:wrap;gap:7px;justify-content:flex-end}
.recon-block-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;padding:14px}
.recon-block{border:1px solid #243750;border-radius:10px;background:#07111e;min-width:0}
.recon-block.wide{grid-column:1/-1}
.recon-block h5{margin:0;padding:11px 12px;border-bottom:1px solid #243750;color:var(--blue);font-size:11px;text-transform:uppercase;letter-spacing:.7px}
.recon-block-body{padding:11px 12px}
.recon-clean-list{list-style:none;margin:0;padding:0;display:grid;gap:6px;max-height:255px;overflow:auto}
.recon-clean-list li{padding:7px 8px;border:1px solid #243750;border-radius:7px;background:#0d1c2f;overflow-wrap:anywhere}
.recon-muted{color:var(--muted)}
.recon-hit-summary{display:flex;flex-wrap:wrap;gap:9px;margin-bottom:12px}
.recon-hit-table{width:100%;min-width:1080px;border-collapse:collapse}
.recon-hit-table th{font-size:10px;letter-spacing:.7px;text-transform:uppercase;color:var(--muted);text-align:left;padding:10px;background:#091522;border-bottom:1px solid var(--line)}
.recon-hit-table td{padding:10px;border-bottom:1px solid rgba(36,55,80,.65);vertical-align:top}
.recon-url{font-family:Consolas,monospace;color:#bfdbfe;overflow-wrap:anywhere}
@media(max-width:1180px){.recon-kpis{grid-template-columns:repeat(3,1fr)}.recon-layout{grid-template-columns:1fr}.recon-list{max-height:260px}.recon-block-grid{grid-template-columns:1fr}}
@media(max-width:680px){.recon-kpis{grid-template-columns:repeat(2,1fr)}.recon-detail-head{display:block}.recon-head-badges{justify-content:flex-start;margin-top:10px}}
</style>
"""
    if "scan-titan-recon-v2" not in patched:
        patched = patched.replace("</head>", recon_css + "</head>")
    recon_start = "let reconView='targets',reconQuery='';const recon=data.recon||{};"
    recon_end = "function unique(k){return"
    recon_js = """
let reconView='targets',reconQuery='',reconSelected='';const recon=data.recon||{};
function arr(v){return Array.isArray(v)?v:(v?[String(v)]:[])}
function compact(v,max=80){const raw=arr(v).flatMap(x=>String(x).split(/\\s*(?:\\n|\\||;|, )\\s*/)).map(x=>x.trim()).filter(Boolean),out=[];for(const item of raw){if(!out.some(x=>x.toLowerCase()===item.toLowerCase()))out.push(item);if(out.length>=max)break}return out}
function chips(v,max=14){const items=compact(v,max+1);return items.length?`<div class="chips">${items.slice(0,max).map(x=>`<span class="chip">${esc(x)}</span>`).join('')}${items.length>max?`<span class="chip muted">+${items.length-max} mas</span>`:''}</div>`:'<span class="recon-muted">N/D</span>'}
function cleanList(v,max=28){const items=compact(v,max+1);return items.length?`<ul class="recon-clean-list">${items.slice(0,max).map(x=>`<li>${esc(x)}</li>`).join('')}${items.length>max?`<li class="recon-muted">+${items.length-max} registro(s) adicionales en Recon_Matrix.xlsx</li>`:''}</ul>`:'<span class="recon-muted">N/D</span>'}
function reconMatch(row){const q=reconQuery.toLowerCase();return !q||JSON.stringify(row).toLowerCase().includes(q)}
function reconCount(key){return (recon.targets||[]).reduce((n,r)=>n+compact(r[key]).length,0)}
function reconMetric(label,value){return `<div class="recon-kpi"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`}
function reconBlock(title,value,wide=false,type='chips'){return `<section class="recon-block ${wide?'wide':''}"><h5>${esc(title)}</h5><div class="recon-block-body">${type==='list'?cleanList(value):chips(value)}</div></section>`}
function renderReconHits(){const rows=(recon.hits||[]).filter(reconMatch).slice(0,500);$('reconScope').textContent=`${rows.length} rutas filtradas · ${recon.summary?.rutas||0} rutas registradas`;return `<div class="recon-shell"><div class="recon-hit-summary">${reconMetric('Rutas visibles',rows.length)}${reconMetric('Total registrado',recon.summary?.rutas||0)}${reconMetric('Objetivos',recon.summary?.targets||0)}${reconMetric('WAF detectados',recon.summary?.waf||0)}${reconMetric('Tecnologias',recon.summary?.tecnologias||0)}</div><div class="table-wrap"><table class="recon-hit-table"><thead><tr><th>Estado</th><th>Objetivo</th><th>Ruta / URL</th><th>Clasificacion</th><th>Soft-404</th><th>Evidencia</th></tr></thead><tbody>${rows.length?rows.map(h=>`<tr><td>${badge(esc(h.status||'N/D'),`status-${esc(h.status)}`)}</td><td>${esc(h.target||'N/D')}</td><td class="recon-url">${esc(h.url||h.path||'')}</td><td>${esc(h.clasificacion||'N/D')}</td><td>${esc(h.soft404||'N/D')}</td><td>${esc(h.evidencia||h.marcador||'')}</td></tr>`).join(''):'<tr><td colspan="6"><div class="empty">No hay rutas para el filtro actual.</div></td></tr>'}</tbody></table></div></div>`}
function renderReconTargets(){const rows=(recon.targets||[]).filter(reconMatch);if(!reconSelected&&rows[0])reconSelected=rows[0].target;let selected=rows.find(r=>r.target===reconSelected)||rows[0];$('reconScope').textContent=`${rows.length} objetivo(s) visibles · WAF en ${recon.summary?.waf||0} objetivo(s)`;if(!selected)return '<div class="empty">No hay objetivos de reconocimiento para el filtro actual.</div>';const detail=`<article class="recon-detail"><div class="recon-detail-head"><div><span class="eyebrow">${esc(selected.tipo||'Objetivo')}</span><h4>${esc(selected.target||'N/D')}</h4><p>${esc(selected.url||selected.ip||'Sin URL base')}</p></div><div class="recon-head-badges">${selected.ip?badge(esc(selected.ip),'status-NOT_SEEN'):''}${selected.ultima?badge(`Actualizado ${esc(selected.ultima.slice(0,19))}`,'status-NEW'):''}${selected.waf||selected.wafw00f?badge('WAF/CDN observado','status-REGRESSION'):badge('Sin WAF confirmado','status-NOT_SEEN')}</div></div><div class="recon-block-grid">${reconBlock('WAF / CDN',arr(selected.waf).concat(selected.wafw00f?[selected.wafw00f]:[],selected.perfil_waf?[selected.perfil_waf]:[]),true,'list')}${reconBlock('Puertos y servicios',arr(selected.puertos).concat(arr(selected.servicios)),false,'list')}${reconBlock('Tecnologias',arr(selected.tecnologias).concat(arr(selected.whatweb)),false,'chips')}${reconBlock('Rutas y endpoints descubiertos',selected.rutas,true,'list')}${reconBlock('Login y subdominios',arr(selected.login).concat(arr(selected.subdominios)),false,'list')}${reconBlock('Headers y cookies',arr(selected.headers).concat(selected.cookies?[selected.cookies]:[]),false,'list')}${reconBlock('Librerias JavaScript',selected.js,true,'list')}</div></article>`;const list=`<aside class="recon-list">${rows.map(r=>`<button class="recon-target ${r.target===selected.target?'active':''}" data-recon-select="${esc(r.target)}"><span><strong>${esc(r.target||'N/D')}</strong><small>${esc(r.ip||r.url||'Sin IP/URL')}</small></span><em>${compact(r.rutas).length} rutas</em></button>`).join('')}</aside>`;return `<div class="recon-shell"><div class="recon-kpis">${reconMetric('Objetivos',rows.length)}${reconMetric('Puertos',recon.summary?.puertos||0)}${reconMetric('Tecnologias',recon.summary?.tecnologias||0)}${reconMetric('Rutas',recon.summary?.rutas||0)}${reconMetric('WAF/CDN',recon.summary?.waf||0)}</div><div class="recon-layout">${list}${detail}</div></div>`}
function renderRecon(){const body=$('reconBody');if(!body)return;if(!recon.available){body.innerHTML='<div class="empty">Recon Matrix aun no esta disponible. Ejecuta un escaneo para poblarla.</div>';$('reconScope').textContent='Sin matriz de reconocimiento';return}body.innerHTML=reconView==='hits'?renderReconHits():renderReconTargets()}
renderRecon();
""".strip()
    if recon_start in patched and recon_end in patched:
        prefix, rest = patched.split(recon_start, 1)
        _, suffix = rest.split(recon_end, 1)
        patched = prefix + recon_js + recon_end + suffix
    patched = patched.replace(
        "document.addEventListener('click',e=>{const i=e.target.closest('[data-inspect]');",
        "document.addEventListener('click',e=>{const rs=e.target.closest('[data-recon-select]');"
        "if(rs){reconSelected=rs.dataset.reconSelect;renderRecon();return}"
        "const i=e.target.closest('[data-inspect]');",
    )
    return patched


def generar_dashboard(df: pd.DataFrame) -> None:
    if df.empty and cargar_estado_hallazgos() is None:
        print("[-] No hay datos para generar el reporte.")
        return
    model = construir_modelo(df)
    output = Path(ARCHIVO_SALIDA)
    output.parent.mkdir(parents=True, exist_ok=True)
    page = HTML_TEMPLATE.replace("__DASHBOARD_DATA__", _json_for_html(model))
    output.write_text(_patch_dashboard_html(page), encoding="utf-8")
    print(f"[+] DASHBOARD v{DASHBOARD_VERSION} GENERADO: {output.resolve()} | activos={model['meta']['active']} historicos={model['meta']['not_seen']}")


def main() -> int:
    generar_dashboard(obtener_dataframe())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
