# -*- coding: utf-8 -*-
"""
OWASP Top 10 2025 normalization helpers for Scan Titan reports.

The scanner keeps report-facing categories in Spanish because the technical
detail template uses those exact labels, while still accepting legacy OWASP
2021/API 2023 inputs from modules and external tools.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any


OWASP_2025_CATEGORIES_ES = {
    "A01": "A01:2025 - Falla de control de acceso",
    "A02": "A02:2025 - Configuración de seguridad incorrecta",
    "A03": "A03:2025 - Fallos en la cadena de suministro de software",
    "A04": "A04:2025 - Fallos criptográficos",
    "A05": "A05:2025 - Inyección",
    "A06": "A06:2025 - Diseño inseguro",
    "A07": "A07:2025 - Fallos de autenticación",
    "A08": "A08:2025 - Fallos de integridad de software o datos",
    "A09": "A09:2025 - Fallos de registro y alertas",
    "A10": "A10:2025 - Manejo inadecuado de condiciones excepcionales",
}

OWASP_2025_CATEGORIES_EN = {
    "A01": "A01:2025 - Broken Access Control",
    "A02": "A02:2025 - Security Misconfiguration",
    "A03": "A03:2025 - Software Supply Chain Failures",
    "A04": "A04:2025 - Cryptographic Failures",
    "A05": "A05:2025 - Injection",
    "A06": "A06:2025 - Insecure Design",
    "A07": "A07:2025 - Authentication Failures",
    "A08": "A08:2025 - Software or Data Integrity Failures",
    "A09": "A09:2025 - Logging and Alerting Failures",
    "A10": "A10:2025 - Mishandling of Exceptional Conditions",
}

OWASP_2021_TO_2025 = {
    "A01": "A01",
    "A02": "A04",
    "A03": "A05",
    "A04": "A06",
    "A05": "A02",
    "A06": "A03",
    "A07": "A07",
    "A08": "A08",
    "A09": "A09",
    "A10": "A01",
}

OWASP_API_2023_TO_2025 = {
    "API1": "A01",
    "API2": "A07",
    "API3": "A01",
    "API4": "A06",
    "API5": "A01",
    "API6": "A01",
    "API7": "A02",
    "API8": "A06",
    "API9": "A02",
    "API10": "A02",
}

CWE_TO_OWASP_2025 = {
    "CWE-22": "A01",
    "CWE-77": "A05",
    "CWE-78": "A05",
    "CWE-79": "A05",
    "CWE-89": "A05",
    "CWE-90": "A05",
    "CWE-94": "A05",
    "CWE-119": "A03",
    "CWE-200": "A02",
    "CWE-295": "A04",
    "CWE-287": "A07",
    "CWE-306": "A01",
    "CWE-319": "A04",
    "CWE-326": "A04",
    "CWE-327": "A04",
    "CWE-346": "A02",
    "CWE-347": "A08",
    "CWE-352": "A01",
    "CWE-384": "A07",
    "CWE-400": "A06",
    "CWE-434": "A06",
    "CWE-521": "A07",
    "CWE-530": "A02",
    "CWE-548": "A02",
    "CWE-611": "A05",
    "CWE-614": "A07",
    "CWE-639": "A01",
    "CWE-693": "A02",
    "CWE-770": "A06",
    "CWE-862": "A01",
    "CWE-918": "A01",
    "CWE-942": "A02",
    "CWE-1021": "A02",
    "CWE-1035": "A03",
    "CWE-1336": "A05",
}

TEXT_RULES = [
    (
        "A05",
        (
            "injection",
            "inyeccion",
            "inyección",
            "sqli",
            "sql injection",
            "xss",
            "command injection",
            "ldap injection",
            "ssti",
            "template injection",
            "payload",
        ),
    ),
    (
        "A01",
        (
            "access control",
            "control de acceso",
            "authorization",
            "autorizacion",
            "autorización",
            "idor",
            "bola",
            "bfla",
            "unauthenticated",
            "sin autenticacion",
            "ssrf",
            "path traversal",
            "lfi",
        ),
    ),
    (
        "A07",
        (
            "authentication",
            "autenticacion",
            "autenticación",
            "login",
            "password",
            "session",
            "cookie",
            "mfa",
            "jwt",
            "bruteforce",
        ),
    ),
    (
        "A04",
        (
            "tls",
            "ssl",
            "certificate",
            "certificado",
            "cryptographic",
            "criptograf",
            "cipher",
            "hsts",
            "https",
            "downgrade",
        ),
    ),
    (
        "A03",
        (
            "component",
            "library",
            "dependency",
            "dependencia",
            "supply chain",
            "cadena de suministro",
            "vulnerable version",
            "cve-",
            "nmap",
            "nuclei",
        ),
    ),
    (
        "A08",
        (
            "integrity",
            "integridad",
            "signature",
            "firma",
            "tamper",
            "source map",
            "sourcemap",
        ),
    ),
    (
        "A09",
        (
            "log",
            "logging",
            "registro",
            "alert",
            "monitor",
        ),
    ),
    (
        "A10",
        (
            "exception",
            "excepcion",
            "excepción",
            "stack trace",
            "traceback",
            "unhandled",
            "error disclosure",
        ),
    ),
    (
        "A06",
        (
            "insecure design",
            "diseño inseguro",
            "business logic",
            "race",
            "rate limit",
            "anti automation",
            "file upload",
        ),
    ),
    (
        "A02",
        (
            "misconfiguration",
            "configuracion",
            "configuración",
            "cors",
            "csp",
            "header",
            "clickjack",
            "cache",
            "server",
            ".git",
            ".env",
            "directory listing",
            "openapi",
            "swagger",
        ),
    ),
]


def normalize_owasp_2025(
    owasp: Any = "",
    *,
    cwe: Any = "",
    category: Any = "",
    title: Any = "",
    source: Any = "",
    evidence: Any = "",
    details: Any = "",
    output: str = "spanish",
) -> str:
    haystack = _normalized(" ".join(map(str, [owasp, cwe, category, title, source, evidence, details])))
    explicit_2025 = re.search(r"\bA(0[1-9]|10)\s*:\s*2025\b", str(owasp or ""), flags=re.IGNORECASE)
    if explicit_2025:
        return _label(f"A{explicit_2025.group(1)}", output)

    for cwe_id in re.findall(r"CWE-\d{1,5}", haystack, flags=re.IGNORECASE):
        code = CWE_TO_OWASP_2025.get(cwe_id.upper())
        if code:
            return _label(code, output)

    for code, needles in TEXT_RULES:
        if any(_normalized(needle) in haystack for needle in needles):
            return _label(code, output)

    api_match = re.search(r"\bAPI\s*(10|[1-9])\s*:\s*2023\b|\bAPI(10|[1-9])\b", str(owasp or ""), re.IGNORECASE)
    if api_match:
        api_number = api_match.group(1) or api_match.group(2)
        return _label(OWASP_API_2023_TO_2025.get(f"API{api_number}", "A02"), output)

    legacy_match = re.search(r"\bA(0[1-9]|10)\s*:\s*2021\b|\bA(0[1-9]|10)\b", str(owasp or ""), re.IGNORECASE)
    if legacy_match:
        legacy_code = f"A{legacy_match.group(1) or legacy_match.group(2)}"
        return _label(OWASP_2021_TO_2025.get(legacy_code, legacy_code), output)

    return _label("A02", output)


def _label(code: str, output: str) -> str:
    categories = OWASP_2025_CATEGORIES_EN if output.lower().startswith("en") else OWASP_2025_CATEGORIES_ES
    return categories.get(code, categories["A02"])


def _normalized(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value or "")
    normalized = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    return normalized.lower()
