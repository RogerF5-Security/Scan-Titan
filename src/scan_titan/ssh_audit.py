"""Build targeted SSH NSE commands and evaluate negotiated server capabilities."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from modules.common import Finding


class NmapSSHAuditor:
    SCRIPTS = 'ssh-auth-methods,ssh2-enum-algos,ssh-hostkey'
    WEAK_KEX = {'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1'}
    WEAK_HOST = {'ssh-dss', 'ssh-rsa'}

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
            # Password/keyboard-interactive support alone is not a vulnerability.
            # NSE auth methods are retained as inventory, including probe username dependence.
            record['missing_scripts'] = sorted(set(cls.SCRIPTS.split(',')) - set(scripts))
            record['state'] = 'partial' if record['errors'] or record['missing_scripts'] else 'observed'
            records.append(record)
        return findings, records
