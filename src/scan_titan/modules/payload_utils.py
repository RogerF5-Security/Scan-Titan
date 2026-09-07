from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import urllib.parse
from typing import Any, Iterable


COMMON_JWT_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "jwt_secret",
    "changeme",
    "test",
    "default",
    "supersecret",
    "mysecret",
    "jwt",
    "token",
    "auth",
    "s3cr3t",
    "p@ssw0rd",
    "letmein",
    "qwerty",
    "abc123",
    "pass",
    "1234567890",
    "secret123",
    "your-256-bit-secret",
    "your_secret_key",
    "secretkey",
    "jwtkey",
    "jwtsecret",
    "jwt_secret_key",
    "my_secret",
    "private_key",
    "signing_key",
    "hmac_secret",
    "api_secret",
    "app_secret",
    "AUTH_SECRET",
    "TOKEN_SECRET",
    "SESSION_SECRET",
    "SECRET_KEY",
    "SIGNING_KEY",
    "PRIVATE_KEY",
    "secret!",
    "p@ssword",
    "passw0rd",
    "Welcome1",
    "Password1",
]


DESTRUCTIVE_PAYLOAD_TOKENS = [
    " drop ",
    "truncate ",
    "delete from",
    "insert into",
    "update ",
    "alter table",
    "create table",
    "shutdown",
    "reboot",
    "mkfs",
    "format ",
    " rm ",
    " rm-",
    "del ",
    "erase ",
    "curl ",
    "wget ",
    "attacker.com",
    "burpcollaborator",
]


def unique_values(*groups: Iterable[Any], limit: int | None = None) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for raw in group or []:
            value = str(raw or "").strip()
            if not value or value in seen:
                continue
            values.append(value)
            seen.add(value)
            if limit and len(values) >= limit:
                return values
    return values


def safe_active_payloads(values: Iterable[str], *, limit: int | None = None) -> list[str]:
    clean: list[str] = []
    for value in values or []:
        text = str(value or "").strip()
        if not text:
            continue
        normalized = f" {text.lower()} "
        if any(token in normalized for token in DESTRUCTIVE_PAYLOAD_TOKENS):
            continue
        clean.append(text)
        if limit and len(clean) >= limit:
            break
    return clean


def url_encode(value: str) -> str:
    return "".join(f"%{ord(char):02X}" for char in value)


def partial_url_encode(value: str) -> str:
    specials = set('<>"\'/();&|`!')
    return "".join(f"%{ord(char):02X}" if char in specials else char for char in value)


def double_url_encode(value: str) -> str:
    return url_encode(value).replace("%", "%25")


def html_decimal_encode(value: str) -> str:
    return "".join(f"&#{ord(char)};" for char in value)


def html_hex_encode(value: str) -> str:
    return "".join(f"&#x{ord(char):02x};" for char in value)


def mixed_case(value: str) -> str:
    out = []
    upper = True
    for char in value:
        if char.isalpha():
            out.append(char.upper() if upper else char.lower())
            upper = not upper
        else:
            out.append(char)
    return "".join(out)


def newline_tag_encode(value: str) -> str:
    return re.sub(
        r"(</?)(script|img|svg|iframe|body|input|div)",
        lambda match: match.group(1) + "%0a".join(match.group(2)),
        value,
        flags=re.IGNORECASE,
    )


def xss_bypass_variants(payload: str) -> list[str]:
    variants = [
        url_encode(payload),
        double_url_encode(payload),
        html_decimal_encode(payload),
        html_hex_encode(payload),
        mixed_case(payload),
        newline_tag_encode(payload),
    ]
    if "alert(1)" in payload:
        variants.extend(
            [
                payload.replace("alert(1)", "alert`1`"),
                payload.replace("alert(1)", "prompt(1)"),
                payload.replace("alert(1)", "confirm(1)"),
                payload.replace("alert(1)", "window['alert'](1)"),
                payload.replace("alert(1)", "top['ale'+'rt'](1)"),
            ]
        )
    return unique_values(variants)


def sqli_bypass_variants(payload: str) -> list[str]:
    variants = [
        partial_url_encode(payload),
        double_url_encode(payload),
        payload.replace(" ", "/**/"),
        payload.replace(" ", "%09"),
        payload.replace(" ", "%0a"),
        payload.replace(" ", "+"),
    ]
    if "UNION" in payload.upper():
        variants.extend(
            [payload.replace("UNION", "UNI/**/ON"), payload.replace("UNION", "UnIoN")]
        )
    if "SELECT" in payload.upper():
        variants.extend(
            [payload.replace("SELECT", "SEL/**/ECT"), payload.replace("SELECT", "SeLeCt")]
        )
    return unique_values(variants)


def xss_payloads(wordlists: dict[str, list[str]], defaults: list[str], *, limit: int) -> list[str]:
    wordlist_xss = [payload for payload in wordlists.get("xss", [])[:limit] if _looks_like_xss_payload(payload)]
    seeds = unique_values(
        wordlists.get("xss_payloads", [])[:limit],
        wordlist_xss,
        defaults,
    )
    bypasses: list[str] = []
    for payload in seeds[: min(len(seeds), 64)]:
        bypasses.extend(xss_bypass_variants(payload))
    return safe_active_payloads(unique_values(seeds, bypasses), limit=limit * 2)


def _looks_like_xss_payload(payload: str) -> bool:
    text = str(payload or "").strip()
    if not text:
        return False
    lower = text.lower()
    sql_noise = [
        " union ",
        " select ",
        " or 1=1",
        " or \"1\"=\"1",
        " or '1'='1",
        " sleep(",
        "benchmark(",
        "pg_sleep",
        "--",
    ]
    if any(token in f" {lower} " for token in sql_noise):
        return False
    xss_markers = [
        "<script",
        "</script",
        "<img",
        "<svg",
        "<iframe",
        "<body",
        "<input",
        "<details",
        "<video",
        "<audio",
        "<object",
        "<embed",
        "<math",
        "<form",
        "javascript:",
        "data:text/html",
        "srcdoc",
        "onerror",
        "onload",
        "onclick",
        "onmouseover",
        "onfocus",
        "ontoggle",
        "onbegin",
        "alert(",
        "confirm(",
        "prompt(",
        "%3c",
        "&#x3c",
        "\\x3c",
    ]
    return any(marker in lower for marker in xss_markers)


def sqli_payloads(wordlists: dict[str, list[str]], defaults: list[str], *, limit: int) -> list[str]:
    seeds = safe_active_payloads(unique_values(defaults, wordlists.get("sqli", [])[:limit]), limit=limit)
    bypasses: list[str] = []
    for payload in seeds[: min(len(seeds), 64)]:
        bypasses.extend(sqli_bypass_variants(payload))
    return safe_active_payloads(unique_values(seeds, bypasses), limit=limit * 2)


def command_payloads(wordlists: dict[str, list[str]], defaults: list[str], *, limit: int) -> list[str]:
    values = unique_values(defaults, wordlists.get("command_injection", [])[:limit])
    return safe_active_payloads(values, limit=limit)


def command_markers(payload: str) -> list[str]:
    lower = payload.lower()
    markers = []
    if "scan_titan_marker" in lower:
        markers.append("scan_titan_marker")
    if "whoami" in lower:
        markers.extend(["\\", "nt authority", "www-data", "apache", "nginx", "iis apppool"])
    if re.search(r"(^|[;&|`$()\s])id([;&|`\s)]|$)", lower):
        markers.extend(["uid=", "gid=", "groups="])
    if "uname" in lower:
        markers.extend(["linux", "gnu/linux"])
    if "ipconfig" in lower:
        markers.extend(["windows ip configuration", "ethernet adapter"])
    if re.search(r"(^|[;&|`\s])dir([;&|`\s]|$)", lower):
        markers.extend(["volume in drive", "directory of"])
    return unique_values(markers)


def lfi_payloads(
    wordlists: dict[str, list[str]],
    defaults: list[tuple[str, str]],
    *,
    limit: int,
) -> list[tuple[str, str]]:
    pairs = list(defaults)
    for payload in wordlists.get("lfi", [])[:limit]:
        marker = lfi_marker(payload)
        if marker:
            pairs.append((payload, marker))
    seen = set()
    out = []
    for payload, marker in pairs:
        key = (payload, marker)
        if key in seen:
            continue
        seen.add(key)
        out.append((payload, marker))
        if len(out) >= limit:
            break
    return out


def lfi_marker(payload: str) -> str:
    lower = str(payload or "").lower()
    if "passwd" in lower:
        return "root:x:"
    if "shadow" in lower:
        return "root:"
    if "/etc/hosts" in lower or lower.endswith("etc/hosts"):
        return "localhost"
    if "resolv.conf" in lower:
        return "nameserver"
    if "/etc/issue" in lower:
        return "ubuntu"
    if "win.ini" in lower or "boot.ini" in lower:
        return "[extensions]"
    if "drivers" in lower and "hosts" in lower:
        return "localhost"
    if "php://filter" in lower or "base64-encode" in lower:
        return "PD9waHA"
    if "/proc/" in lower:
        return "uid"
    if ".env" in lower:
        return "APP_KEY"
    if "wp-config.php" in lower:
        return "DB_NAME"
    if "config.php" in lower:
        return "<?php"
    if "application.properties" in lower:
        return "spring."
    if "application.yml" in lower:
        return "spring:"
    if "appsettings.json" in lower:
        return "ConnectionStrings"
    if "web.xml" in lower:
        return "<web-app"
    if "web.config" in lower:
        return "<configuration"
    return ""


def ssti_payloads(
    wordlists: dict[str, list[str]],
    defaults: list[tuple[str, str]],
    *,
    limit: int,
) -> list[tuple[str, str]]:
    pairs = list(defaults)
    for payload in wordlists.get("ssti", [])[:limit]:
        marker = ssti_marker(payload)
        if marker:
            pairs.append((payload, marker))
    seen = set()
    out = []
    for payload, marker in pairs:
        key = (payload, marker)
        if key in seen:
            continue
        seen.add(key)
        out.append((payload, marker))
        if len(out) >= limit:
            break
    return out


def ssti_marker(payload: str) -> str:
    compact = str(payload or "").replace(" ", "")
    if "7*7" in compact or "7*'7'" in compact:
        return "49"
    if "6*7" in compact:
        return "42"
    if "9*9" in compact:
        return "81"
    return ""


def ssrf_payloads(
    wordlists: dict[str, list[str]],
    safe_defaults: list[tuple[str, str]],
    cloud_defaults: list[tuple[str, str]],
    *,
    allow_cloud: bool,
    limit: int,
) -> list[tuple[str, str]]:
    pairs = list(safe_defaults)
    if allow_cloud:
        pairs.extend(cloud_defaults)
    for payload in wordlists.get("ssrf", [])[:limit]:
        marker = ssrf_marker(payload)
        if not marker:
            continue
        if is_cloud_metadata_url(payload) and not allow_cloud:
            continue
        pairs.append((payload, marker))
    seen = set()
    out = []
    for payload, marker in pairs:
        key = (payload, marker)
        if key in seen:
            continue
        seen.add(key)
        out.append((payload, marker))
        if len(out) >= limit:
            break
    return out


def ssrf_marker(payload: str) -> str:
    lower = str(payload or "").lower()
    if "169.254.169.254" in lower or "metadata.google" in lower:
        return "metadata"
    if "kubernetes.default" in lower:
        return "kubernetes"
    if "127." in lower or "localhost" in lower or "[::1]" in lower:
        return "localhost"
    if any(token in lower for token in ["10.", "172.16.", "192.168."]):
        return "internal"
    if "file://" in lower and "passwd" in lower:
        return "root:x:"
    return ""


def is_cloud_metadata_url(payload: str) -> bool:
    lower = str(payload or "").lower()
    return any(token in lower for token in ["169.254.169.254", "metadata.google", "metadata/instance"])


def jwt_decode(token: str) -> tuple[dict[str, Any], dict[str, Any], str, list[str]]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {}, {}, "", parts
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header if isinstance(header, dict) else {}, payload if isinstance(payload, dict) else {}, parts[2], parts
    except Exception:
        return {}, {}, "", parts


def b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode())


def jwt_weak_secret(token: str, secrets: Iterable[str], *, limit: int) -> str:
    header, _payload, signature, parts = jwt_decode(token)
    alg = str(header.get("alg", "HS256"))
    funcs = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    if alg not in funcs or len(parts) != 3:
        return ""
    try:
        target_signature = b64url_decode(signature)
    except Exception:
        return ""
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    for secret in unique_values(COMMON_JWT_SECRETS, secrets, limit=limit):
        computed = hmac.new(secret.encode(), signing_input, funcs[alg]).digest()
        if computed == target_signature:
            return secret
    return ""


def jwt_temporal_claims(payload: dict[str, Any]) -> list[str]:
    issues = []
    now = int(time.time())
    exp = payload.get("exp")
    if exp is None:
        issues.append("No expiration claim (exp)")
    else:
        try:
            delta = int(exp) - now
            if delta > 86400 * 30:
                issues.append(f"Long expiration window: {delta // 86400} days")
        except Exception:
            issues.append("Invalid expiration claim (exp)")
    if "iat" not in payload:
        issues.append("No issued-at claim (iat)")
    if "nbf" not in payload:
        issues.append("No not-before claim (nbf)")
    return issues
