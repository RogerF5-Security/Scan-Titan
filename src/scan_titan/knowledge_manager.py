from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any

from modules.common import Finding, clean_text


STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "this",
    "that",
    "una",
    "uno",
    "con",
    "del",
    "las",
    "los",
    "por",
    "para",
    "que",
    "esta",
    "este",
    "esto",
    "como",
    "servicio",
    "servidor",
    "aplicacion",
    "aplicación",
    "vulnerabilidad",
    "identificado",
}

GENERIC_CWES = {"CWE-1035", "CWE-287", "CWE-693", "CWE-200"}

FAMILY_TERMS: dict[str, tuple[str, ...]] = {
    "sqli": ("sql injection", "inyeccion sql", "cwe-89"),
    "command_injection": ("command injection", "inyeccion de comandos", "cwe-78"),
    "ssti": ("ssti", "server side template injection", "template injection", "cwe-1336"),
    "ssrf": ("ssrf", "server side request forgery", "cwe-918"),
    "xss": ("cross site scripting", " xss ", "cwe-79"),
    "cors": ("cors", "access control allow origin", "cwe-942"),
    "open_redirect": ("open redirect", "external redirect", "redireccion externa", "cwe-601"),
    "debug": ("debug mode", "debug configuration", "django debug", "stack trace", "traceback"),
    "javascript": ("javascript library", "jquery", "prototype pollution", "npm", "cwe-1104"),
    "tls_certificate": ("tls certificate", "ssl certificate", "self signed", "expired ssl", "cwe-295"),
    "weak_cipher": ("weak cipher", "cipher suite", "sslv2", "poodle", "cwe-326"),
    "headers": ("security header", "content security policy", " csp ", "hsts", "cwe-693"),
    "cookie": ("cookie", "httponly", "samesite", "cwe-614"),
    "path_traversal": ("path traversal", "directory traversal", " lfi ", "cwe-22"),
    "file_upload": ("file upload", "unrestricted upload", "cwe-434"),
    "csrf": (" csrf ", "cross site request forgery", "cwe-352"),
    "idor": (" idor ", "broken object level authorization", " bola ", "cwe-639"),
    "xxe": (" xxe ", "xml external entity", "cwe-611"),
    "jwt": (" jwt ", "json web token", "cwe-347"),
}


def normalize_text(value: Any) -> str:
    text = str(value or "").lower()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = re.sub(r"[^a-z0-9._:/+-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def owasp_code(value: str) -> str:
    match = re.search(r"\b(A\d{2})\s*:?\s*2025\b", str(value or ""), flags=re.IGNORECASE)
    return match.group(1).upper() if match else ""


def tokens(value: str) -> set[str]:
    return {
        token
        for token in normalize_text(value).split()
        if len(token) >= 3 and token not in STOPWORDS and not token.isdigit()
    }


def vulnerability_families(value: Any) -> set[str]:
    normalized = f" {normalize_text(value)} "
    return {
        family
        for family, terms in FAMILY_TERMS.items()
        if any(f" {normalize_text(term)} " in normalized for term in terms)
    }


class KnowledgeBase:
    def __init__(self, path: Path, entries: list[dict[str, Any]], min_score: float = 7.0) -> None:
        self.path = path
        self.entries = entries
        self.min_score = float(min_score)

    @classmethod
    def load(cls, path: Path, min_score: float = 7.0) -> "KnowledgeBase":
        if not path.exists():
            return cls(path, [], min_score)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return cls(path, [], min_score)
        entries = payload.get("entries", []) if isinstance(payload, dict) else []
        clean_entries = [entry for entry in entries if isinstance(entry, dict)]
        return cls(path, clean_entries, min_score)

    def apply(self, finding: Finding) -> None:
        entry, score = self.best_match(finding)
        if not entry:
            return

        entry_cwe = str(entry.get("cwe") or "")
        entry_owasp = str(entry.get("owasp") or "")
        entry_cvss = str(entry.get("cvss") or "")
        finding_cves = {item.upper() for item in re.findall(r"CVE-\d{4}-\d{4,7}", self._finding_text(finding), re.I)}
        entry_cves = {str(item).upper() for item in entry.get("cves", []) if str(item).strip()}
        exact_cve = bool(finding_cves.intersection(entry_cves))
        family_match = bool(
            vulnerability_families(self._finding_text(finding)).intersection(
                vulnerability_families(self._entry_text(entry))
            )
        )
        strong_context = exact_cve or (family_match and score >= 9.0)
        if entry_cwe and (not finding.cwe or (strong_context and finding.cwe in GENERIC_CWES)):
            finding.cwe = entry_cwe
        if entry_owasp and (not finding.owasp or (strong_context and entry_cwe == finding.cwe)):
            finding.owasp = entry_owasp
        if entry_cvss and not finding.cvss and strong_context:
            finding.cvss = entry_cvss

        impact = entry.get("impact") or entry.get("description_general")
        recommendation = entry.get("recommendation") or entry.get("remediation")
        finding.impact = finding.impact or clean_text(impact, 1600)
        finding.remediation = finding.remediation or clean_text(recommendation, 1600)
        finding.recommendation = finding.recommendation or clean_text(recommendation, 1600)

        detail = entry.get("description_detail") if exact_cve else entry.get("description_general")
        if detail and "Scan Titan KB" not in str(finding.details):
            kb_note = (
                f"Scan Titan KB: {clean_text(entry.get('title'), 220)} "
                f"(score={score:.1f}, observed={entry.get('observed_count', 1)})"
            )
            label = "Contexto CVE validado" if exact_cve else "Contexto general de la base"
            kb_description = f"{label}: {clean_text(detail, 1800)}"
            finding.details = " | ".join(
                part for part in [finding.details, kb_note, kb_description] if part
            )

    def best_match(self, finding: Finding) -> tuple[dict[str, Any] | None, float]:
        if not self.entries:
            return None, 0.0
        finding_text = self._finding_text(finding)
        normalized = normalize_text(finding_text)
        finding_tokens = tokens(finding_text)
        finding_cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", finding_text, flags=re.IGNORECASE))
        finding_cves = {item.upper() for item in finding_cves}
        finding_owasp = owasp_code(finding.owasp)
        finding_families = vulnerability_families(finding_text)
        best_entry: dict[str, Any] | None = None
        best_score = 0.0

        for entry in self.entries:
            score = 0.0
            entry_text = self._entry_text(entry)
            entry_families = vulnerability_families(entry_text)
            if finding_families and entry_families and finding_families.isdisjoint(entry_families):
                continue
            finding_cwe = normalize_text(finding.cwe)
            entry_cwe_text = normalize_text(entry.get("cwe"))
            if (
                finding_cwe
                and entry_cwe_text
                and finding_cwe != entry_cwe_text
                and str(finding.cwe).upper() not in GENERIC_CWES
                and str(entry.get("cwe") or "").upper() not in GENERIC_CWES
            ):
                continue
            entry_cves = {str(item).upper() for item in entry.get("cves", []) if str(item).strip()}
            if entry_cves and finding_cves and not finding_cves.intersection(entry_cves):
                continue
            if entry_cves and not finding_cves:
                score -= 3.0
            if finding_cves and finding_cves.intersection(entry_cves):
                score += 8.0
            elif finding_cves and not entry_cves:
                score -= 4.0
            if finding.cwe and normalize_text(finding.cwe) == normalize_text(entry.get("cwe")):
                score += 3.0
            entry_owasp = owasp_code(str(entry.get("owasp", "")))
            if finding_owasp and entry_owasp == finding_owasp:
                score += 2.0

            alias_hits = 0
            for alias in entry.get("aliases", []):
                alias_norm = normalize_text(alias)
                if len(alias_norm) >= 3 and alias_norm in normalized:
                    alias_hits += 1
            score += min(alias_hits, 3) * 2.5

            term_hits = 0
            for term in entry.get("match_terms", []):
                term_norm = normalize_text(term)
                if len(term_norm) >= 3 and term_norm in normalized:
                    term_hits += 1
            score += min(term_hits, 5) * 1.2

            title_tokens = tokens(str(entry.get("title", "")))
            if title_tokens and finding_tokens:
                overlap = len(title_tokens.intersection(finding_tokens))
                score += (overlap / max(1, len(title_tokens))) * 4.0

            if score > best_score:
                best_entry = entry
                best_score = score

        if best_entry and best_score >= self.min_score:
            return best_entry, best_score
        return None, best_score

    @staticmethod
    def _finding_text(finding: Finding) -> str:
        return " ".join(
            [
                finding.category,
                finding.title,
                finding.source,
                finding.evidence,
                finding.details,
                finding.cwe,
                finding.owasp,
                finding.cvss,
            ]
        )

    @staticmethod
    def _entry_text(entry: dict[str, Any]) -> str:
        return " ".join(
            [
                str(entry.get("title") or ""),
                " ".join(str(item) for item in entry.get("aliases", []) or []),
                " ".join(str(item) for item in entry.get("match_terms", []) or []),
                str(entry.get("cwe") or ""),
                str(entry.get("owasp") or ""),
            ]
        )
