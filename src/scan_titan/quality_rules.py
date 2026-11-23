"""Dependency-free Scan Titan finding quality rules."""

from __future__ import annotations

from typing import Any
from finding_triage import injection_family


def finding_quality_exclusion(finding: Any) -> str:
    """Return a deterministic exclusion reason for proven scanner artifacts."""

    def value(name: str, fallback: str = "") -> str:
        if isinstance(finding, dict):
            return str(finding.get(name) or finding.get(fallback) or "")
        return str(getattr(finding, name, "") or getattr(finding, fallback, "") or "")

    title = value("title").lower()
    source = value("source").lower()
    param = value("param").strip().lower()
    confidence = value("confidence").strip().lower()
    # State records keep the latest proof in last_evidence.
    evidence = " ".join([value("evidence", "last_evidence"), value("details")]).lower()
    if title in {"front-end storage/cookie access pattern", "dom xss sink indicators detected"} or title.startswith("front-end token/secret exposed:"):
        return "static_client_side_indicator_requires_validation"
    status_text = value("status", "http").strip()
    validation = finding.get("validation", {}) if isinstance(finding, dict) else getattr(finding, "validation", {})
    if injection_family(finding) and (not isinstance(validation, dict) or validation.get("state") != "CONFIRMED"
                                      or validation.get('version') != 'differential-v1'):
        return "injection_requires_independent_differential_validation"
    try:
        status = int(status_text)
    except (TypeError, ValueError):
        status = 0

    if (
        (source == "zap:40018" or "zap: inyección sql" in title or "zap: sql injection" in title)
        and param in {"host", "host header", "http host"}
        and confidence != "high"
    ):
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
        if not any(marker in evidence for marker in database_errors):
            return "unconfirmed_zap_sqli_host_header_variance"

    if source == "zap:90022" and "parent directory" in evidence:
        return "zap_application_error_duplicate_of_directory_listing"

    if title == "modern tls protocol support not confirmed":
        return "tls_probe_failure_is_not_proof_of_legacy_only_protocols"

    if "command injection" in title and "scan_titan_marker" in evidence and status >= 400:
        return "legacy_command_marker_reflected_in_error_response"
    if title.startswith("ssrf signal:") and status != 200:
        return "legacy_ssrf_signal_without_successful_internal_response"
    return _unproven_reason(title, _sources(finding, source), evidence)


ZAP_ACTIVE_RULE_MIN_ID = 20000
_EMPTY_ZAP_EVIDENCE = ("evidencia=- ", "evidence=- ", "evidencia=-|", "evidence=-|")


def _sources(finding: Any, source: str) -> set[str]:
    values = finding.get("correlated_sources") if isinstance(finding, dict) else getattr(finding, "correlated_sources", None)
    if isinstance(values, str):
        values = values.split(",")
    items = {str(item).strip().lower() for item in (values or []) if str(item).strip()}
    if source:
        items.add(source)
    return items


def _unproven_reason(title: str, sources: set[str], evidence: str) -> str:
    """Findings whose stored evidence cannot demonstrate the vulnerability.

    They stay visible as 'Por validar' in the Daily instead of being counted as
    vulnerabilities. Rules are evidence-based, so a record produced by a newer
    engine with real proof is not affected.
    """
    compact = evidence.replace(" | ", "|")
    if title.startswith("componente con aviso de seguridad:") and " | " in title:
        return "version_advisory_superseded_by_component_summary"
    if title.startswith("exposed log/debug content:") and (
        "log/debug markers observed" in evidence or "marcadores de log/debug observados" in evidence
    ):
        return "legacy_log_marker_without_log_structure"
    if (title.startswith("exposed or restricted path:") and "confirmedcontent=false" in evidence
            and "marcadores=" not in evidence):
        return "path_without_content_proof"
    if "nmap:http-slowloris-check" in sources or ("cve-2007-6750" in title and "nmap" in title):
        if "likely vulnerable" in evidence or "probablemente vulnerable" in evidence:
            return "slowloris_nse_heuristic_requires_manual_validation"
    if "nmap:http-vuln-cve2011-3192" in sources or "cve-2011-3192" in title:
        return "byterange_nse_check_requires_version_validation"
    if "nmap:vulners" in sources or "cves potenciales inferidos" in title or "potential cves inferred" in title:
        # vulners maps the CPE/banner version to every CVE ever published for it;
        # distribution backports (e.g. OpenSSH 8.9p1-3ubuntu0.x) are not visible.
        return "nmap_vulners_version_correlation_requires_validation"
    for item in sources:
        if not item.startswith("zap:"):
            continue
        try:
            plugin = int(item.split(":", 1)[1])
        except (IndexError, ValueError):
            continue
        if plugin < ZAP_ACTIVE_RULE_MIN_ID:
            continue
        no_evidence = any(marker in compact + " " for marker in _EMPTY_ZAP_EVIDENCE) or compact.endswith(
            ("evidencia=-", "evidence=-"))
        weak = "confianza=high" not in compact and "confidence=high" not in compact
        if no_evidence and weak:
            return "zap_active_alert_without_response_evidence"
    return ""
