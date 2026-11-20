"""Build targeted SSH NSE commands and evaluate negotiated server capabilities."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from modules.common import Finding


def _openssh_tuple(text: str) -> tuple[int, int, int] | None:
    """Parse '8.9p1' -> (8, 9, 1); missing portable suffix counts as p0."""
    match = re.match(r'\s*(\d+)\.(\d+)(?:p(\d+))?', str(text or ''))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _numeric_parts(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r'\d+', text))


# Upstream-vulnerable OpenSSH server CVEs, matched by version range only.
# Each entry: (cve, title, severity, cvss, cwe, low_inclusive, high_exclusive, impact, fix)
OPENSSH_VERSION_CVES = (
    ('CVE-2024-6387', 'OpenSSH regreSSHion: condicion de carrera del manejador SIGALRM', 'High',
     '8.1 (High)', 'CWE-364', (8, 5, 1), (9, 8, 1),
     'Ejecucion remota de codigo como root sin autenticacion en sshd sobre glibc/Linux '
     '(explotacion probabilistica, requiere miles de intentos).',
     'Actualizar a OpenSSH 9.8p1+ o al paquete corregido del proveedor; mitigacion temporal '
     'LoginGraceTime 0 (expone a agotamiento de conexiones).'),
    ('CVE-2025-26466', 'OpenSSH: agotamiento de memoria/CPU pre-autenticacion (SSH2_MSG_PING)', 'Medium',
     '5.9 (Medium)', 'CWE-770', (9, 5, 0), (9, 9, 2),
     'Un cliente sin autenticar puede consumir memoria y CPU del servidor de forma asimetrica (DoS).',
     'Actualizar a OpenSSH 9.9p2+ o paquete corregido; limitar con LoginGraceTime, MaxStartups y PerSourcePenalties.'),
    ('CVE-2018-15473', 'OpenSSH: enumeracion de usuarios validos', 'Medium',
     '5.3 (Medium)', 'CWE-203', (0, 0, 0), (7, 7, 0),
     'Respuestas distintas para usuarios existentes permiten confirmar cuentas validas antes de fuerza bruta.',
     'Actualizar OpenSSH a 7.7+ o al paquete corregido del proveedor; restringir SSH por ACL/VPN.'),
)

# Distribution package builds that already carry the CVE-2024-6387 fix
# (USN-6859-1, DSA-5724-1). Banner text -> minimum fixed revision.
REGRESSHION_FIXED_BUILDS = {
    ('ubuntu', (8, 9, 1)): (3, 0, 10),    # jammy 1:8.9p1-3ubuntu0.10
    ('ubuntu', (9, 3, 1)): (1, 3, 6),     # mantic 1:9.3p1-1ubuntu3.6
    ('ubuntu', (9, 6, 1)): (3, 13, 3),    # noble 1:9.6p1-3ubuntu13.3
    ('debian', (9, 2, 1)): (2, 12, 3),    # bookworm 1:9.2p1-2+deb12u3
}


class NmapSSHAuditor:
    SCRIPTS = 'ssh-auth-methods,ssh2-enum-algos,ssh-hostkey,sshv1'
    # sshv1 emits output only when the server accepts protocol 1; absence is the
    # expected secure result, not missing coverage.
    OPTIONAL_SCRIPTS = {'sshv1'}
    WEAK_KEX = {'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1'}
    WEAK_HOST = {'ssh-dss', 'ssh-rsa'}
    STRICT_KEX_MARKER = 'kex-strict-s-v00@openssh.com'

    @classmethod
    def terrapin_exposure(cls, algorithms: dict[str, list[str]]) -> dict[str, Any] | None:
        """CVE-2023-48795: prefix truncation needs ChaCha20-Poly1305 or CBC+EtM
        and no strict-kex countermeasure advertised by the server."""
        def group(*names: str) -> list[str]:
            items: list[str] = []
            for key, values in algorithms.items():
                if any(name in key for name in names):
                    items.extend(values)
            return items

        kex = group('kex')
        if not kex:
            return None
        if cls.STRICT_KEX_MARKER in kex:
            return None
        ciphers = group('encryption')
        macs = group('mac')
        chacha = [name for name in ciphers if name.startswith('chacha20-poly1305')]
        cbc = [name for name in ciphers if name.endswith('-cbc')]
        etm = [name for name in macs if name.endswith('-etm@openssh.com')]
        if not chacha and not (cbc and etm):
            return None
        return {'chacha20': chacha, 'cbc': cbc, 'etm_macs': etm, 'strict_kex': False}

    @classmethod
    def version_findings(cls, target: str, port_number: str, service: Any) -> list[Finding]:
        if service is None or 'openssh' not in str(service.get('product', '')).lower():
            return []
        raw_version = str(service.get('version', '') or '')
        upstream = _openssh_tuple(raw_version)
        if upstream is None:
            return []
        banner = f"{service.get('product', '')} {raw_version} {service.get('extrainfo', '')}".strip()
        lowered = raw_version.lower()
        distro = 'ubuntu' if 'ubuntu' in lowered else ('debian' if 'debian' in lowered else '')
        has_vendor_suffix = bool(re.search(r'\d+p\d+\s+\S', raw_version))
        findings: list[Finding] = []
        for cve, title, severity, cvss, cwe, low, high, impact, fix in OPENSSH_VERSION_CVES:
            if not (low <= upstream < high):
                continue
            confidence = 'medium'
            note = 'Version upstream dentro del rango afectado; sin sufijo de paquete de distribucion.'
            if cve == 'CVE-2024-6387' and distro:
                fixed = REGRESSHION_FIXED_BUILDS.get((distro, upstream))
                revision_text = raw_version.split(None, 1)[1] if ' ' in raw_version else ''
                revision = _numeric_parts(revision_text)
                if fixed and revision and revision >= fixed:
                    continue
                if not fixed:
                    confidence = 'low'
                    note = f'Paquete {distro} sin build corregido conocido en el catalogo; verificar backport.'
                else:
                    note = f'Build {distro} anterior al corregido {".".join(map(str, fixed))}.'
            elif has_vendor_suffix:
                confidence = 'low'
                note = 'Banner con sufijo de proveedor: el paquete puede incluir backport; verificar avisos.'
            findings.append(Finding(
                target=target, category='SSH', severity=severity,
                title=f'{title} ({cve})', endpoint=f'{port_number}/tcp',
                source='nmap:ssh-version-correlation', confidence=confidence,
                evidence=f'Banner: {banner}; rango afectado {".".join(map(str, low))} <= v < '
                         f'{".".join(map(str, high))}. {note}',
                evidence_strength='Version correlation; vendor patch state unverified',
                false_positive_risk='Medium', cwe=cwe, cvss=cvss, impact=impact,
                remediation=fix, recommendation=fix,
                details='Correlacion por version; no se ejecuto ninguna prueba de explotacion.'))
        return findings

    @classmethod
    def command(cls, binary: str, host: str, ports: list[int], output: Path,
                username: str = 'scan_titan_probe') -> list[str]:
        if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', username):
            raise ValueError('Invalid SSH probe username')
        valid_ports = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})
        if not valid_ports:
            raise ValueError('No SSH ports selected')
        return [binary, '-sV', '-v', '-Pn', '-p', ','.join(map(str, valid_ports)),
                '--script', cls.SCRIPTS, '--script-args', f'ssh.user={username}',
                '--script-timeout', '30s', '--host-timeout', '180s', '-oX', str(output), host]

    @classmethod
    def parse(cls, target: str, xml: str) -> tuple[list[Finding], list[dict[str, Any]]]:
        root = ET.fromstring(xml)
        findings: list[Finding] = []
        records: list[dict[str, Any]] = []
        for port in root.findall('.//port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            port_number = port.get('portid', '')
            scripts = {script.get('id'): script for script in port.findall('script')}
            if not any(name in scripts for name in cls.SCRIPTS.split(',')):
                continue
            record: dict[str, Any] = {'port': port_number, 'algorithms': {}, 'auth_methods': [], 'host_keys': [], 'errors': []}
            for sid, script in scripts.items():
                output = script.get('output', '')
                if 'error' in output.lower():
                    record['errors'].append(sid)
                if sid == 'ssh-auth-methods':
                    methods = [str(node.text or '').strip() for node in script.findall('.//elem')
                               if (node.text or '').strip() in {'password', 'publickey', 'keyboard-interactive', 'none', 'hostbased', 'gssapi-with-mic'}]
                    if not methods:
                        methods = re.findall(r'(?m)^\s*(password|publickey|keyboard-interactive|none|hostbased|gssapi-with-mic)\s*$', output)
                    record['auth_methods'] = sorted(set(methods))
                elif sid == 'ssh2-enum-algos':
                    for table in script.findall('table'):
                        key = str(table.get('key', ''))
                        record['algorithms'][key] = [str(node.text or '').strip() for node in table.findall('.//elem')]
                    # Older NSE releases expose the same data only in the output attribute.
                    if not record['algorithms']:
                        group = ''
                        for line in output.splitlines():
                            match = re.match(r'\s*(\w+):?\s*\(\d+\)', line)
                            if match:
                                group = match.group(1)
                                record['algorithms'][group] = []
                            elif group and line.strip():
                                record['algorithms'][group].append(line.strip())
                elif sid == 'ssh-hostkey':
                    for table in script.findall('table'):
                        record['host_keys'].append({node.get('key'): node.text for node in table.findall('elem')})
            weak: dict[str, list[str]] = {}
            for group, algorithms in record['algorithms'].items():
                if not any(part in group for part in ('kex', 'encryption', 'mac', 'server_host_key')):
                    continue
                matches = [name for name in algorithms if (
                    name in cls.WEAK_KEX or name in cls.WEAK_HOST
                    or 'arcfour' in name or name == '3des-cbc' or name.endswith('-cbc')
                    or name.startswith('hmac-md5') or name in {'hmac-sha1-96', 'none'})]
                if matches:
                    weak[group] = matches
            short_keys = []
            for key in record['host_keys']:
                try:
                    bits = int(key.get('bits') or 0)
                except ValueError:
                    continue
                key_type = str(key.get('type') or '')
                if ('rsa' in key_type.lower() and 0 < bits < 2048) or 'dss' in key_type.lower() or 'dsa' in key_type.lower():
                    short_keys.append(f'{key_type}:{bits}')
            if weak:
                findings.append(Finding(
                    target=target, category='SSH', severity='Medium',
                    title='SSH server offers legacy or weak cryptographic algorithms',
                    endpoint=f'{port_number}/tcp', source='nmap:ssh2-enum-algos', confidence='high',
                    evidence=str(weak), cwe='CWE-327',
                    recommendation='Disable the listed legacy algorithms and verify modern client compatibility.'))
            if short_keys:
                findings.append(Finding(
                    target=target, category='SSH', severity='Medium', title='SSH weak host key',
                    endpoint=f'{port_number}/tcp', source='nmap:ssh-hostkey', confidence='high',
                    evidence=', '.join(short_keys), cwe='CWE-326'))
            terrapin = cls.terrapin_exposure(record['algorithms'])
            record['terrapin'] = terrapin or {'exposed': False}
            if terrapin:
                findings.append(Finding(
                    target=target, category='SSH', severity='Medium',
                    title='SSH vulnerable a Terrapin (CVE-2023-48795): truncamiento de prefijo',
                    endpoint=f'{port_number}/tcp', source='nmap:ssh2-enum-algos', confidence='high',
                    evidence=f'ChaCha20-Poly1305={terrapin["chacha20"]}; CBC={terrapin["cbc"]}; '
                             f'EtM MACs={terrapin["etm_macs"]}; {cls.STRICT_KEX_MARKER} no anunciado',
                    evidence_strength='Negotiated algorithm list (same criterion as ssh-audit/Terrapin scanner)',
                    false_positive_risk='Low', cwe='CWE-354', cvss='5.9 (Medium)',
                    impact='Un atacante en posicion MitM puede eliminar mensajes iniciales del canal cifrado '
                           '(p. ej. degradar extensiones de autenticacion) sin ser detectado.',
                    remediation='Actualizar a OpenSSH 9.6+ (strict kex) o deshabilitar chacha20-poly1305@openssh.com '
                                'y los MAC *-etm@openssh.com combinados con cifrados CBC.',
                    recommendation='Aplicar strict kex (OpenSSH 9.6+) o retirar ChaCha20-Poly1305 y CBC+EtM.'))
            sshv1 = scripts.get('sshv1')
            if sshv1 is not None and 'Server supports SSHv1' in sshv1.get('output', ''):
                findings.append(Finding(
                    target=target, category='SSH', severity='High', title='SSH admite el protocolo SSHv1',
                    endpoint=f'{port_number}/tcp', source='nmap:sshv1', confidence='high',
                    evidence=sshv1.get('output', '')[:500], cwe='CWE-327', cvss='7.4 (High)',
                    recommendation='Configurar exclusivamente Protocol 2 o actualizar a OpenSSH >= 7.4.'))
            findings.extend(cls.version_findings(target, port_number, port.find('service')))
            # Password/keyboard-interactive support alone is not a vulnerability.
            # NSE auth methods are retained as inventory, including probe username dependence.
            record['missing_scripts'] = sorted(
                set(cls.SCRIPTS.split(',')) - set(scripts) - cls.OPTIONAL_SCRIPTS)
            record['state'] = 'partial' if record['errors'] or record['missing_scripts'] else 'observed'
            records.append(record)
        return findings, records
