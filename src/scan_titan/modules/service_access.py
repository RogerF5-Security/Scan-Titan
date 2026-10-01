"""Service access runs independently of the HTTP circuit breaker."""
from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

from .common import Finding, ScanContext, VulnerabilityModule


class ServiceAccessAuditor(VulnerabilityModule):
    name = "service_access"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        from service_audit import service_findings

        config = ctx.policy.stateful.get("services", {})
        if config.get("enabled", True) is False:
            ctx.recon["service_access"] = [{"state": "disabled"}]
            return []
        host = ctx.target.ip or ctx.target.host
        ports = {"ftp": set(config.get("ftp_ports", [21])), "smb": set(config.get("smb_ports", [445, 139]))}
        for item in ctx.recon.get("ports_services", []):
            match = re.match(r"(\d+)/tcp:\s*(.*)", str(item))
            if match:
                service = match.group(2).lower()
                if re.search(r"\bftp\b", service):
                    ports["ftp"].add(int(match.group(1)))
                elif any(name in service for name in ("microsoft-ds", "netbios-ssn", "smb")):
                    ports["smb"].add(int(match.group(1)))
        findings: list[Finding] = []
        records = ctx.recon.setdefault("service_access", [])
        already = {(r.get("protocol"), r.get("port")) for r in records}
        for protocol, candidates in ports.items():
            for port in sorted({int(p) for p in candidates if 1 <= int(p) <= 65535})[:8]:
                if (protocol, port) in already:
                    continue
                control = ctx.limits.runtime_control
                if control and control.finish_requested:
                    return findings
                try:
                    _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 2)
                    writer.close()
                    await writer.wait_closed()
                except OSError as exc:
                    records.append({"protocol": protocol, "port": port, "state": "unreachable",
                                    "error": type(exc).__name__})
                    continue
                except asyncio.TimeoutError:
                    records.append({"protocol": protocol, "port": port, "state": "timeout"})
                    continue
                options = {"protocol": protocol, "host": host, "port": port, "timeout": 5}
                if protocol == "smb":
                    options.update(shares=config.get("smb_shares", ["SharedDocs", "Public", "Users", "C$", "ADMIN$"]),
                                   max_shares=8, allow_nmap=ctx.policy.enable_nmap and not ctx.policy.skip_external)
                record = await self._worker(options)
                records.append(record)
                findings.extend(service_findings(ctx.target.display, record))
                ctx.heartbeat(self.name, f'{protocol}:{port} {record["state"]}', len(records), len(findings))
        return findings

    @staticmethod
    async def _worker(options: dict) -> dict:
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-B", str(Path(__file__).resolve().parents[1] / "service_audit.py"),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            **({'creationflags': subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
               if os.name == 'nt' else {'start_new_session': True}))
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(options).encode()), 60)
            if process.returncode:
                return {"protocol": options["protocol"], "port": options["port"], "state": "error",
                        "error": stderr.decode(errors="replace")[-400:]}
            return json.loads(stdout)
        except asyncio.TimeoutError:
            return {"protocol": options["protocol"], "port": options["port"], "state": "timeout"}
        finally:
            if process.returncode is None:
                if os.name == 'nt':
                    killer = await asyncio.create_subprocess_exec(
                        'taskkill', '/PID', str(process.pid), '/T', '/F',
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NO_WINDOW)
                    await killer.wait()
                else:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                await process.communicate()
