"""Publication leak gate: block client data before files leave the workspace.

The denylist is built only from local, private sources and never written to
disk or printed in full:
  * hosts/IPs in targets/targets.txt (active and commented lines)
  * host names embedded in audit_reports/ file names (coverage_<host>_..., <host>_<date>.json)
  * extra entries in config/leak_denylist.local.txt (one per line, optional, git-ignored)
Each file to publish is also checked for generic secrets and personal paths.

Usage:
  python -B tools/leak_gate.py PATH [PATH ...]          # files or directories to publish
  python -B tools/leak_gate.py --workspace ROOT PATH... # read targets/reports from ROOT
Exit code 0 = clean, 1 = leaks found (each reported as file:line and rule, values masked).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TEXT_SUFFIXES = {".py", ".md", ".txt", ".yaml", ".yml", ".json", ".html", ".js", ".cjs", ".ps1", ".sh", ".cmd",
                 ".toml", ".csv", ".nse", ".cfg", ".ini", ".xml"}
GENERIC_RULES = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("windows-user-path", re.compile(r"[A-Za-z]:\\\\?Users\\\\?(?!Public\b|Default\b)[A-Za-z0-9._-]+", re.I)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@(?!example\.(?:com|org|net)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]
# Technical identifiers (SSH algorithm names), test fixtures and public sample data.
EMAIL_ALLOW = re.compile(r"noreply@anthropic\.com|@users\.noreply\.github\.com|^security@|"
                         r"@(?:openssh\.com|libssh\.org|juice-sh\.op|[a-z0-9.-]+\.(?:test|invalid|local|example|op))$",
                         re.I)
EMAIL_EXEMPT_DIRS = {"wordlists"}
HOST_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}|\b(?:\d{1,3}\.){3}\d{1,3}\b", re.I)
SAFE_HOSTS = {"example.com", "example.org", "example.net", "127.0.0.1", "0.0.0.0", "localhost"}


def _hosts_from_text(text: str) -> set[str]:
    hosts = set()
    for line in text.splitlines():
        value = line.strip().lstrip("#").strip()
        value = re.sub(r"^[a-z]+://", "", value, flags=re.I).split("/")[0].split(":")[0].split("?")[0]
        if value and HOST_RE.fullmatch(value):
            hosts.add(value.lower())
    return hosts


def build_denylist(workspace: Path) -> set[str]:
    hosts: set[str] = set()
    targets = workspace / "targets" / "targets.txt"
    if targets.is_file():
        hosts |= _hosts_from_text(targets.read_text(encoding="utf-8", errors="replace"))
    reports = workspace / "audit_reports"
    if reports.is_dir():
        for path in reports.iterdir():
            match = re.match(r"(?:coverage_|recon_intelligence_|ffuf_out_|whatweb_out_)?([a-z0-9.-]+\.[a-z]{2,})[_.]",
                             path.name, re.I)
            if match:
                hosts.add(match.group(1).lower())
    extra = workspace / "config" / "leak_denylist.local.txt"
    if extra.is_file():
        hosts |= {line.strip().lower() for line in extra.read_text(encoding="utf-8").splitlines()
                  if line.strip() and not line.startswith("#")}
    # Registrable parents too (fac.client.com.gt -> client.com.gt) so sibling hosts are caught.
    for host in list(hosts):
        parts = host.split(".")
        if len(parts) >= 3 and not re.fullmatch(r"[\d.]+", host):
            hosts.add(".".join(parts[-3:] if parts[-2] in {"com", "gob", "org", "net", "edu"} else parts[-2:]))
    # RFC 2606 names and RFC 5737 documentation ranges are examples, never clients.
    documentation = ("192.0.2.", "198.51.100.", "203.0.113.")
    return {host for host in hosts if host not in SAFE_HOSTS and not host.endswith((".example", ".invalid", ".test"))
            and not host.startswith(documentation) and not host.endswith(("example.com", "example.org", "example.net"))}


def mask(value: str) -> str:
    return value[:2] + "***" + value[-2:] if len(value) > 6 else "***"


def scan_file(path: Path, denylist: set[str]) -> list[str]:
    if path.suffix.lower() not in TEXT_SUFFIXES or path.stat().st_size > 5_000_000:
        return []
    problems = []
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        lower = line.lower()
        for host in denylist:
            if host in lower:
                problems.append(f"{path}:{number}: host de cliente ({mask(host)})")
        for rule, pattern in GENERIC_RULES:
            if rule == "email" and EMAIL_EXEMPT_DIRS & set(path.parts):
                continue
            for match in pattern.finditer(line):
                if rule == "email" and EMAIL_ALLOW.search(match.group()):
                    continue
                problems.append(f"{path}:{number}: {rule} ({mask(match.group())})")
    return problems


def iter_files(paths: list[Path]):
    for item in paths:
        if item.is_dir():
            for path in item.rglob("*"):
                if path.is_file() and not any(part in {".git", "__pycache__", "audit_reports", "version_backups", "whatweb", "bin"}
                                              for part in path.parts):
                    yield path
        elif item.is_file():
            yield item


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    denylist = build_denylist(args.workspace)
    problems = [problem for path in iter_files(args.paths) for problem in scan_file(path, denylist)]
    print(f"leak_gate: {len(denylist)} hosts privados en la lista de bloqueo; {len(problems)} hallazgo(s).")
    for problem in problems[:200]:
        print("  " + problem)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
