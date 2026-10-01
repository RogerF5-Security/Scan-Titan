"""Bounded, read-only FTP and SMB access checks; no passwords or file writes."""
from __future__ import annotations

import ftplib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def audit_ftp(host: str, port: int, timeout: float = 5) -> dict[str, Any]:
    record: dict[str, Any] = {"protocol": "ftp", "port": port, "state": "error",
                              "anonymous_login": False, "listing": False}
    client = ftplib.FTP_TLS(context=ssl._create_unverified_context(), timeout=timeout)
    try:
        record["banner"] = client.connect(host, port)[:250]
        try:
            client.auth()
            record["tls"] = "supported"
        except ftplib.error_perm as exc:
            if str(exc)[:3] not in {"500", "502", "504", "530", "534"}:
                raise
            record["tls"] = "unavailable"
        reply = client.login("anonymous", "scan-titan@example.invalid", secure=False)
        record["anonymous_login"] = reply.startswith("230")
        record["state"] = "observed"
        if not record["anonymous_login"]:
            return record
        if record["tls"] == "supported":
            client.prot_p()
        # ftplib ignores the advertised PASV address by default: data stays on host.
        names: list[str] = []

        def receive(line: str) -> None:
            names.append(line[:180])
            if len(names) >= 20:
                raise StopIteration

        try:
            client.retrlines("LIST", receive)
            record["listing"] = True
        except StopIteration:
            record["listing"] = True
        except ftplib.error_perm as exc:
            record["listing_error"] = str(exc)[:200]
        record["entries_sample"] = names[:5]
        record["entries_observed"] = len(names)
    except ftplib.error_perm as exc:
        record["state"] = "denied" if str(exc).startswith("530") else "error"
        record["error"] = str(exc)[:200]
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {str(exc)[:180]}"
    finally:
        client.close()
    return record


def audit_smb_nmap(host: str, port: int, shares: list[str]) -> dict[str, Any]:
    record: dict[str, Any] = {"protocol": "smb", "port": port, "state": "partial", "sessions": [],
                              "backend": "nmap_smb1", "note": "Acceso SMB1; SMB2/3 requiere Impacket."}
    binary = shutil.which("nmap")
    if not binary:
        for folder in (os.environ.get("ProgramFiles(x86)", ""), os.environ.get("ProgramFiles", "")):
            candidate = Path(folder) / "Nmap/nmap.exe"
            if candidate.is_file():
                binary = str(candidate)
                break
    if not binary:
        return {**record, "state": "dependency_missing", "error": "Nmap e Impacket no disponibles"}
    safe_shares = [s for s in shares[:8] if re.fullmatch(r"[A-Za-z0-9_.$ -]{1,80}", s) and s.upper() != "IPC$"]
    script = Path(__file__).parent / "nse/titan-smb-access.nse"
    args = f"smbport={port},titan-smb-access.shares={{{','.join(safe_shares)}}}"
    command = [binary, "-sT", "-Pn", "-n", "-p", str(port), "--script", str(script),
               "--script-args", args, "--script-timeout", "45s", "--host-timeout", "50s", "-oX", "-", host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=55,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        record["returncode"] = result.returncode
        root = ET.fromstring(result.stdout)
        record.update(parse_smb_access_xml(root))
        if result.returncode:
            record["state"] = "error"
            record["error"] = result.stderr[-300:]
    except Exception as exc:
        record.update(state="error", error=f"{type(exc).__name__}: {str(exc)[:180]}")
    return record


def parse_smb_access_xml(root: ET.Element) -> dict[str, Any]:
    result: dict[str, Any] = {"sessions": []}
    script = root.find(".//script[@id='titan-smb-access']")
    if script is None:
        return {**result, "state": "partial", "error": "SMB1 script produced no structured evidence"}
    for table in script.findall("table"):
        fields = {e.get("key"): e.text or "" for e in table.findall("elem")}
        accepted = fields.get("accepted") == "true"
        session = {"identity": table.get("key", ""), "accepted": accepted,
                   "guest_mapping": fields.get("guest_mapping") == "true", "shares": []}
        if not accepted:
            session["error"] = fields.get("error", "")
        else:
            result["dialect"] = "NT LM 0.12"
            result["os"] = fields.get("os", "")
            result["server_name"] = fields.get("server", "")
        for share in table.findall("table"):
            details = {e.get("key"): e.text or "" for e in share.findall("elem")}
            session["shares"].append({"name": share.get("key", ""), "list_root": details.get("list_root") == "true",
                                      "entries_observed": details.get("entries_observed", "0")})
        result["sessions"].append(session)
    return result


def audit_smb(host: str, port: int, timeout: float = 5,
              shares: list[str] | None = None, max_shares: int = 8,
              allow_nmap: bool = True) -> dict[str, Any]:
    record: dict[str, Any] = {"protocol": "smb", "port": port, "state": "error", "sessions": []}
    try:
        from impacket.smbconnection import SMBConnection
    except (ImportError, OSError):
        if not allow_nmap:
            return {**record, "state": "dependency_missing", "error": "Impacket unavailable; Nmap disabled by policy"}
        return audit_smb_nmap(host, port, shares or ["SharedDocs", "Public", "Users", "C$", "ADMIN$"])
    deadline = time.monotonic() + 45
    for username in ("", "Guest"):
        session: dict[str, Any] = {"identity": "null" if not username else "Guest/empty-password",
                                   "accepted": False, "shares": []}
        record["sessions"].append(session)
        client = None
        try:
            client = SMBConnection(host if port != 139 else "*SMBSERVER", host,
                                   sess_port=port, timeout=timeout)
            client.login(username, "")
            session["accepted"] = True
            session["guest_mapping"] = bool(client.isGuestSession())
            record["os"] = client.getServerOS()
            record["server_name"] = client.getServerName()
            record["dialect"] = str(client.getDialect())
            record["signing_required"] = bool(client.isSigningRequired())
            record["state"] = "observed"
            candidates = list(shares or [])
            try:
                enumerated = client.listShares()
                session["share_enumeration"] = True
                for item in enumerated:
                    # Disk shares only; IPC access does not prove access to files.
                    if int(item["shi1_type"]) & 0xFFFF == 0:
                        candidates.append(str(item["shi1_netname"]).rstrip("\x00"))
            except Exception as exc:
                session["enumeration_error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
            for share in list(dict.fromkeys(candidates))[:max(1, min(max_shares, 20))]:
                if time.monotonic() >= deadline:
                    record["state"] = "partial"
                    break
                if not share or share.upper() == "IPC$" or any(x in share for x in ("/", "\\", "\x00")):
                    continue
                item = {"name": share, "list_root": False}
                session["shares"].append(item)
                try:
                    entries = client.listPath(share, "*")
                    item["list_root"] = True
                    item["entries_sample"] = [e.get_longname()[:160] for e in entries[:5]]
                    item["entries_observed"] = len(entries)
                except Exception as exc:
                    item["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
        except Exception as exc:
            message = str(exc)
            session["state"] = "denied" if any(code in message for code in (
                "STATUS_LOGON_FAILURE", "STATUS_ACCESS_DENIED", "STATUS_ACCOUNT_DISABLED",
                "STATUS_ACCOUNT_RESTRICTION")) else "error"
            session["error"] = f"{type(exc).__name__}: {message[:180]}"
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
        if time.monotonic() >= deadline:
            record["state"] = "partial"
            break
    if record["state"] == "error" and all(s.get("state") == "denied" for s in record["sessions"]):
        record["state"] = "denied"
    elif any(s.get("state") == "error" for s in record["sessions"]):
        record["state"] = "partial"
    return record


def service_findings(target: str, record: dict[str, Any]) -> list[Any]:
    from modules.common import Finding

    protocol = record["protocol"]
    endpoint = f'{record["port"]}/tcp'
    findings: list[Finding] = []

    def add(title: str, severity: str, evidence: str, cwe: str, fix: str) -> None:
        findings.append(Finding(target=target, category=protocol.upper(), severity=severity,
                                title=title, endpoint=endpoint, source="service_access",
                                confidence="high", evidence_strength="strong", evidence=evidence,
                                cwe=cwe, recommendation=fix))

    if protocol == "ftp" and record.get("anonymous_login"):
        add("FTP: acceso anonimo con listado de directorio" if record.get("listing") else
            "FTP: inicio de sesion anonimo permitido; listado no demostrado", "Medium",
            f'USER anonymous / PASS de contacto; login=230; LIST={record.get("listing")}; '
            f'banner={record.get("banner", "")}; entries={record.get("entries_observed", 0)}',
            "CWE-306", "Deshabilitar anonymous si no es un servicio publico previsto; limitar directorios y permisos.")
        if record.get("tls") == "unavailable":
            add("FTP: acceso permitido sin cifrado TLS", "Medium", "AUTH TLS rechazado; login anonimo aceptado.",
                "CWE-319", "Exigir FTPS o migrar a SFTP.")
    if protocol == "smb":
        os_name = str(record.get("os") or "SO no determinado")
        server = str(record.get("server_name") or target)
        if re.search(r"\bWindows\s+(?:XP|2000|5\.[01]|Server\s+2003)\b", os_name, re.I):
            add("SMB: sistema operativo heredado sin soporte", "High",
                f"Identificacion anunciada por SMB: {os_name}; servidor={server}. No prueba una CVE concreta.",
                "CWE-1104", "Migrar a un sistema soportado y aislar el servicio SMB heredado.")
        if record.get("dialect") == "NT LM 0.12":
            add("SMBv1 negociado", "Medium", f"Servidor={server}; dialecto=NT LM 0.12",
                "CWE-327", "Deshabilitar SMBv1 y utilizar SMB2/SMB3.")
        if record.get("signing_required") is False:
            add("SMB: firma de mensajes no obligatoria", "Medium", f"Servidor={server}; signing_required=False",
                "CWE-345", "Exigir firma SMB en servidor y clientes.")
        seen: set[str] = set()
        for session in record.get("sessions", []):
            readable = [s for s in session["shares"] if s.get("list_root")]
            for share in readable:
                if share["name"].lower() in seen:
                    continue
                seen.add(share["name"].lower())
                add(f'SMB: recurso {share["name"]} accesible sin credenciales', "High",
                    f'Servidor={server}; SO anunciado={os_name}; identidad={session["identity"]}; '
                    f'guest_mapping={session.get("guest_mapping")}; recurso={share["name"]}; '
                    f'listado de raiz aceptado; entradas={share.get("entries_observed", 0)}; '
                    'lectura de contenido y escritura no probadas.',
                    "CWE-306", "Deshabilitar acceso anonimo/invitado y exigir ACL de recurso y sistema de archivos.")
            if session.get("accepted") and not readable:
                add("SMB: sesion sin credenciales aceptada; acceso a archivos no demostrado", "Info",
                    f'Servidor={server}; SO anunciado={os_name}; identidad={session["identity"]}; '
                    f'enumeracion={session.get("share_enumeration", False)}',
                    "", "Revisar restricciones de sesiones nulas e invitado.")
    return findings


if __name__ == "__main__":
    options = json.loads(sys.stdin.read(16384))
    function = audit_smb if options.pop("protocol") == "smb" else audit_ftp
    print(json.dumps(function(**options), ensure_ascii=True))
