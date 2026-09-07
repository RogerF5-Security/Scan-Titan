"""Dependency-free Scan Titan finding quality rules."""

from __future__ import annotations

from typing import Any


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
    evidence = " ".join([value("evidence"), value("details")]).lower()
    status_text = value("status", "http").strip()
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
    return ""
