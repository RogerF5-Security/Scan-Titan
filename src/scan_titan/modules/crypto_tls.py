from __future__ import annotations

import asyncio
import socket
import ssl
import urllib.parse
from datetime import datetime

from .common import Finding, ScanContext, VulnerabilityModule


class CryptoTlsModule(VulnerabilityModule):
    name = "crypto_tls"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._https_redirect(ctx))
        findings.extend(await self._headers(ctx))
        if ctx.target.scheme == "https" or ctx.target.port == 443:
            findings.extend(await asyncio.to_thread(self._certificate_and_protocols, ctx))
        return findings

    async def _https_redirect(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target.scheme != "https":
            return []
        http_url = urllib.parse.urlunparse(("http", ctx.target.host, "/", "", "", ""))
        result = await ctx.http.request("GET", http_url, allow_redirects=False, timeout=min(ctx.limits.timeout, 5))
        if not result:
            return []
        location = result.headers.get("Location", "")
        if result.status in {301, 302, 307, 308} and location.startswith("https://"):
            return []
        return [
            Finding(
                target=ctx.target.display,
                category="TLS",
                severity="Medium",
                title="HTTP to HTTPS redirect not enforced",
                url=http_url,
                status=str(result.status),
                evidence=f"Location={location or '-'}",
                source=self.name,
                confidence="medium",
            )
        ]

    async def _headers(self, ctx: ScanContext) -> list[Finding]:
        result = await ctx.http.request("GET", ctx.target.url, allow_redirects=True)
        if not result:
            return []
        findings = []
        hsts = result.headers.get("Strict-Transport-Security", "")
        if ctx.target.scheme == "https" and not hsts:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="TLS",
                    severity="Medium",
                    title="HSTS missing",
                    url=result.final_url,
                    evidence="Strict-Transport-Security header not observed.",
                    source=self.name,
                    confidence="high",
                )
            )
        expect_ct = result.headers.get("Expect-CT", "")
        if ctx.target.scheme == "https" and not expect_ct:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="TLS",
                    severity="Info",
                    title="Expect-CT header not present",
                    url=result.final_url,
                    evidence="Expect-CT is deprecated in modern browsers but retained as audit evidence.",
                    source=self.name,
                    confidence="low",
                )
            )
        return findings

    def _certificate_and_protocols(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        host = ctx.target.host
        port = 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=ctx.limits.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    cipher = tls.cipher()
                    version = tls.version()
                    ctx.recon["tls_protocol"] = version or ""
                    ctx.recon["tls_cipher"] = " ".join(str(x) for x in cipher) if cipher else ""
                    if cipher and (int(cipher[2]) < 128 or any(x in cipher[0].upper() for x in ["RC4", "DES", "3DES"])):
                        findings.append(
                            Finding(
                                target=ctx.target.display,
                                category="TLS",
                                severity="High",
                                title="Weak TLS cipher negotiated",
                                url=ctx.target.url,
                                evidence=f"Cipher={cipher}",
                                source=self.name,
                                confidence="medium",
                            )
                        )
                    findings.extend(self._cert_findings(ctx, cert))
        except Exception as exc:
            message = str(exc)
            validation_failed = "CERTIFICATE_VERIFY_FAILED" in message or "certificate verify failed" in message.lower()
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="TLS",
                    severity="Medium" if validation_failed else "Info",
                    title="TLS certificate validation failed" if validation_failed else "TLS certificate inspection failed",
                    url=ctx.target.url,
                    evidence=message,
                    source=self.name,
                    confidence="medium" if validation_failed else "low",
                )
            )

        findings.extend(self._downgrade_checks(ctx, host, port))
        findings.extend(self._modern_protocol_checks(ctx, host, port))
        return findings

    def _cert_findings(self, ctx: ScanContext, cert: dict) -> list[Finding]:
        findings: list[Finding] = []
        if not cert:
            return findings
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        cn = subject.get("commonName", "")
        sans = [value for key, value in cert.get("subjectAltName", []) if key == "DNS"]
        ctx.recon["certificate_cn"] = cn
        ctx.recon["certificate_san"] = sans
        ctx.recon["certificate_issuer"] = issuer.get("organizationName") or issuer.get("commonName") or ""
        if cn and ctx.target.host not in [cn, *sans] and not any(san.startswith("*.") and ctx.target.host.endswith(san[1:]) for san in sans):
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="TLS",
                    severity="High",
                    title="Certificate CN/SAN mismatch",
                    url=ctx.target.url,
                    evidence=f"CN={cn} SAN={sans}",
                    source=self.name,
                    confidence="high",
                )
                )
        not_after = cert.get("notAfter")
        not_before = cert.get("notBefore")
        if not_before:
            try:
                start = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                if start > datetime.utcnow():
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="TLS",
                            severity="High",
                            title="TLS certificate not yet valid",
                            url=ctx.target.url,
                            evidence=f"NotBefore={start.date()}",
                            source=self.name,
                            confidence="high",
                        )
                    )
            except Exception:
                pass
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days = (expiry - datetime.utcnow()).days
            ctx.recon["certificate_expiry"] = f"{expiry.date()} ({days} days)"
            if days < 30:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="TLS",
                        severity="High" if days < 7 else "Medium",
                        title="TLS certificate near expiration",
                        url=ctx.target.url,
                        evidence=f"Expires={expiry.date()} Days={days}",
                        source=self.name,
                        confidence="high",
                    )
                )
        return findings

    def _downgrade_checks(self, ctx: ScanContext, host: str, port: int) -> list[Finding]:
        findings = []
        protocol_tests = [
            ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
            ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ]
        for label, version in protocol_tests:
            if version is None:
                continue
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version
                with socket.create_connection((host, port), timeout=min(ctx.limits.timeout, 5)) as sock:
                    with context.wrap_socket(sock, server_hostname=host):
                        findings.append(
                            Finding(
                                target=ctx.target.display,
                                category="TLS",
                                severity="High",
                                title=f"Obsolete TLS protocol accepted: {label}",
                                url=ctx.target.url,
                                evidence=f"Handshake succeeded with {label}.",
                                source=self.name,
                                confidence="high",
                            )
                        )
            except Exception:
                continue
        return findings

    def _modern_protocol_checks(self, ctx: ScanContext, host: str, port: int) -> list[Finding]:
        accepted: list[str] = []
        protocol_tests = [
            ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
            ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
        ]
        for label, version in protocol_tests:
            if version is None:
                continue
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version
                with socket.create_connection((host, port), timeout=min(ctx.limits.timeout, 5)) as sock:
                    with context.wrap_socket(sock, server_hostname=host):
                        accepted.append(label)
            except Exception:
                continue
        ctx.recon["tls_supported_protocols"] = accepted
        if accepted:
            return []
        return [
            Finding(
                target=ctx.target.display,
                category="TLS",
                severity="High",
                title="Modern TLS protocol support not confirmed",
                url=ctx.target.url,
                evidence="TLSv1.2/TLSv1.3 handshakes did not succeed during protocol validation.",
                source=self.name,
                confidence="medium",
            )
        ]
