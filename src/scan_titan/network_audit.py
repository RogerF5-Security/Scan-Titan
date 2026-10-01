"""Parse targeted SMB NSE evidence, including hostscript (not only port scripts)."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from modules.common import Finding


class NmapNetworkAuditor:
    SCRIPTS = "smb-os-discovery,smb-protocols,smb-security-mode,smb2-security-mode,smb-vuln-ms17-010"

    @classmethod
    def command(cls, binary: str, host: str, output: Path) -> list[str]:
        return [binary, "-sT", "-sV", "-Pn", "-p", "139,445", "--script", cls.SCRIPTS,
                "--script-args", "vulns.showall=true", "--script-timeout", "25s",
                "--host-timeout", "150s", "-oX", str(output), host]

    @classmethod
    def parse(cls, target: str, xml: str) -> tuple[list[Finding], list[dict[str, Any]]]:
        root = ET.fromstring(xml)
        findings: list[Finding] = []
        records: list[dict[str, Any]] = []
        for script in root.findall(".//script"):
            sid = script.get("id", "")
            if sid not in cls.SCRIPTS.split(","):
                continue
            output = script.get("output", "")
            fields = {e.get("key", ""): (e.text or "") for e in script.findall(".//elem")}
            combined = output + "\n" + "\n".join(fields.values())
            record = {"script": sid, "state": "observed", "output": output[:3000], "fields": fields}
            if re.search(r"\bERROR\b|could not|failed|timed out", output, re.I):
                record["state"] = "error"
            records.append(record)
            if record["state"] == "error":
                continue
            title, severity, cwe = "", "Medium", ""
            if sid == "smb-vuln-ms17-010":
                states = [e.text or "" for e in script.findall(".//elem[@key='state']")]
                vulnerable = "VULNERABLE" in states if states else bool(
                    re.search(r"(?m)^\s*State:\s*VULNERABLE\s*$", output))
                record["state"] = "vulnerable" if vulnerable else "not_confirmed"
                if vulnerable:
                    title, severity, cwe = "SMB: MS17-010 detectado por comprobacion NSE", "Critical", "CWE-119"
            elif sid == "smb-protocols" and "NT LM 0.12" in combined:
                title, cwe = "SMBv1 soportado", "CWE-327"
            elif sid in {"smb-security-mode", "smb2-security-mode"}:
                signing = fields.get("message_signing", "").lower()
                if signing in {"disabled", "supported"} or re.search(
                        r"signing (?:enabled but not required|disabled)", combined, re.I):
                    title, cwe = "SMB: firma de mensajes no obligatoria", "CWE-345"
                if fields.get("challenge_response", "").lower() == "unsupported":
                    findings.append(Finding(target=target, category="SMB", severity="High",
                        title="SMB: autenticacion con contrasena en texto claro", source=f"nmap:{sid}",
                        confidence="high", evidence=output[:2000], cwe="CWE-319",
                        recommendation="Deshabilitar autenticacion SMB heredada y exigir SMB2/3 con firma."))
            elif sid == "smb-os-discovery":
                title, severity = "SMB: identificacion del sistema y servidor", "Info"
                if re.search(r"\bWindows\s+(?:XP|2000|5\.[01]|Server\s+2003)\b", combined, re.I):
                    title, severity, cwe = "SMB: sistema operativo heredado sin soporte", "High", "CWE-1104"
            if title:
                findings.append(Finding(target=target, category="SMB", severity=severity, title=title,
                    endpoint="139,445/tcp", source=f"nmap:{sid}", confidence="high", cwe=cwe,
                    evidence=combined[:2000], evidence_strength="strong",
                    details="Comprobacion de protocolo; no se ejecuto codigo remoto ni se probo escritura.",
                    recommendation="Aplicar parches, retirar sistemas sin soporte, deshabilitar SMBv1 y exigir firma."))
        observed = {r["script"] for r in records}
        missing = sorted(set(cls.SCRIPTS.split(",")) - observed)
        if missing:
            open_smb = any(p.get('portid') in {'139', '445'} and p.find("state[@state='open']") is not None
                           for p in root.findall('.//port'))
            records.append({"state": "partial" if open_smb else "not_applicable", "scripts": missing,
                            "note": "Script no aplicable, no respondio o no produjo salida; no equivale a seguro."})
        return findings, records
