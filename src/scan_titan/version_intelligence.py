"""Offline-first, source-attributed component version and support checks."""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiohttp
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


RETIRE_URL = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json'
PHP_URL = 'https://api.github.com/repos/php/php-src/security-advisories?per_page=100'
APACHE_URL = 'https://httpd.apache.org/security/vulnerabilities-httpd.json'
LIFECYCLE_PRODUCTS = ('php', 'python', 'django', 'nodejs', 'openssl',
                      'apache-http-server', 'nginx', 'tomcat', 'jquery', 'dotnet')
ALIASES = {
    'php': 'php', 'apache': 'apache-http-server', 'apache httpd': 'apache-http-server',
    'nginx': 'nginx', 'openssl': 'openssl', 'python': 'python', 'django': 'django',
    'node.js': 'nodejs', 'nodejs': 'nodejs', 'apache tomcat': 'tomcat', 'tomcat': 'tomcat',
    'jquery': 'jquery', 'jquery ui': 'jquery-ui', 'jquery-ui': 'jquery-ui',
    'bootstrap': 'bootstrap', 'angularjs': 'angularjs', 'angular.js': 'angularjs',
    'lodash': 'lodash', 'moment': 'moment.js', 'moment.js': 'moment.js',
    'handlebars': 'handlebars', 'dompurify': 'dompurify', 'axios': 'axios',
    'vue': 'vue', 'react': 'react', 'dotnet': 'dotnet', '.net': 'dotnet',
}
for _library in ('jquery-migrate', 'jquery-validation', 'jquery-mobile', 'knockout',
                 'tinyMCE', 'YUI', 'prototypejs', 'ember', 'dojo', '@angular/core',
                 'backbone.js', 'mustache.js', 'plupload', 'react-dom', 'ckeditor',
                 'ckeditor5', 'ExtJS', 'svelte', 'markdown-it', 'jszip', 'chart.js',
                 'highcharts', 'select2', 'ua-parser-js', 'pdf.js', 'threejs',
                 'highlightjs', 'marked', 'alpinejs', 'd3', 'video.js', 'quill', 'swiper'):
    ALIASES[_library.lower()] = _library
_NAMES = '|'.join(re.escape(name) for name in sorted(ALIASES, key=len, reverse=True))
_COMPONENT_PATTERN = re.compile(
    rf'(?<![\w-])(?P<name>{_NAMES})(?:\.min)?(?:\.js)?[\s/@:_=-]+v?'
    r'(?P<version>\d+(?:\.\d+){1,3}(?:[-+~][A-Za-z0-9._+~-]+)?)', re.I,
)


def extract_components(text: str, url: str, source: str) -> list[dict[str, str]]:
    """Read explicit product/version markers, never guess from age or filenames alone."""
    return [dict(product=ALIASES[m['name'].lower()], version=m['version'], url=url,
                 source=source, evidence=m.group(0)[:180])
            for m in list(_COMPONENT_PATTERN.finditer(text[:65536]))[:30]]


async def download_json(session: aiohttp.ClientSession, url: str) -> Any:
    async with session.get(url) as response:
        response.raise_for_status()
        chunks = bytearray()
        async for chunk in response.content.iter_chunked(65536):
            chunks.extend(chunk)
            if len(chunks) > 5_000_000:
                raise ValueError('catalogo demasiado grande')
        return json.loads(chunks)


class VersionCatalog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {'schema': 1, 'sources': {}}
        self.diagnostics: list[str] = []
        try:
            loaded = json.loads(path.read_text(encoding='utf-8'))
            if loaded.get('schema') == 1 and isinstance(loaded.get('sources'), dict):
                self.data = loaded
        except (OSError, ValueError, AttributeError):
            pass

    async def refresh(self, *, force: bool = False, days: int = 7) -> dict[str, int]:
        """Fetch public catalogs only; no target URLs or inventories leave the machine."""
        urls = {'retirejs': RETIRE_URL, 'php_advisories': PHP_URL, 'apache_advisories': APACHE_URL}
        urls.update({f'eol:{p}': f'https://endoflife.date/api/v1/products/{p}/'
                     for p in LIFECYCLE_PRODUCTS})
        semaphore = asyncio.Semaphore(3)
        changed = 0
        now = dt.datetime.now(dt.timezone.utc)
        sources = dict(self.data['sources'])

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),
                                         headers={'User-Agent': 'Scan-Titan-Version-Catalog/1.0',
                                                  'Accept-Encoding': 'gzip, deflate'}) as session:
            async def fetch(key: str, url: str) -> None:
                nonlocal changed
                old = sources.get(key, {})
                try:
                    age = now - dt.datetime.fromisoformat(old.get('fetched_at', ''))
                    if not force and age < dt.timedelta(days=days):
                        return
                except (ValueError, TypeError):
                    pass
                async with semaphore:
                    try:
                        parsed = await download_json(session, url)
                        if key == 'php_advisories' and isinstance(parsed, list) and len(parsed) == 100:
                            for page in range(2, 11):
                                batch = await download_json(session, f'{url}&page={page}')
                                if not isinstance(batch, list):
                                    raise ValueError('pagina de avisos PHP invalida')
                                parsed.extend(batch)
                                if len(batch) < 100:
                                    break
                            else:
                                raise ValueError('paginacion PHP incompleta; se conserva cache anterior')
                        if key == 'retirejs':
                            valid = isinstance(parsed, dict) and 'jquery' in parsed
                        elif key in {'php_advisories', 'apache_advisories'}:
                            valid = isinstance(parsed, list) and bool(parsed) and all(isinstance(r, dict) for r in parsed)
                        else:
                            result = parsed.get('result') if isinstance(parsed, dict) else None
                            valid = isinstance(result, dict) and isinstance(result.get('releases'), list)
                        if not valid:
                            raise ValueError('esquema de catalogo inesperado')
                        raw = json.dumps(parsed, sort_keys=True, separators=(',', ':')).encode()
                        sources[key] = dict(url=url, fetched_at=now.isoformat(),
                                            sha256=hashlib.sha256(raw).hexdigest(), data=parsed)
                        changed += 1
                    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
                        self.diagnostics.append(f'{key}: {str(exc)[:150]}')

            tasks = [asyncio.create_task(fetch(k, u)) for k, u in urls.items()]
            try:
                await asyncio.wait_for(asyncio.gather(*tasks), timeout=35)
            except asyncio.TimeoutError:
                self.diagnostics.append('Actualizacion parcial: limite global de 35s')
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        if changed:
            self.data = dict(schema=1, sources=sources)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix('.tmp')
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
            tmp.replace(self.path)
        return {'sources': len(sources), 'updated': changed, 'errors': len(self.diagnostics)}

    def source(self, key: str) -> Any:
        return self.data['sources'].get(key, {}).get('data', {})

    def issues(self, product: str, version: str, today: dt.date | None = None) -> list[dict[str, Any]]:
        # Distribution suffixes may identify backported fixes. Never strip them.
        if not re.fullmatch(r'\d+(?:\.\d+){1,3}', version):
            return []
        current = Version(version)
        today = today or dt.date.today()
        issues: list[dict[str, Any]] = []
        releases = self.source(f'eol:{product}').get('result', {}).get('releases', [])
        for release in sorted(releases, key=lambda r: len(str(r.get('name', ''))), reverse=True):
            cycle = str(release.get('name', ''))
            if version != cycle and not version.startswith(cycle + '.'):
                continue
            date = release.get('eolFrom')
            if isinstance(date, str) and date[:10] < today.isoformat():
                issues.append(dict(id=f'EOL-{product}-{cycle}', kind='eol', severity='Medium',
                                   cycle=cycle,
                                   fixed='rama con soporte de seguridad',
                                   reference=f'https://endoflife.date/{product}',
                                   detail=f'Rama {cycle}; soporte de seguridad finalizado el {date[:10]}'))
            break
        if len(version.split('.')) < 3:
            return issues
        retire = self.source('retirejs')
        library = next((v for k, v in retire.items() if k.lower() == product.lower()), {})
        for item in library.get('vulnerabilities', []):
            try:
                if not item.get('below') or current >= Version(item['below']):
                    continue
                if item.get('atOrAbove') and current < Version(item['atOrAbove']):
                    continue
            except InvalidVersion:
                continue
            ids = item.get('identifiers', {})
            identifier = ','.join(ids.get('CVE', [])) or ids.get('githubID') or f"RETIRE-{ids.get('retid', item['below'])}"
            if identifier.startswith('CVE-XXXX'):
                continue
            issues.append(dict(id=identifier, kind='advisory', severity=str(item.get('severity', 'medium')).title(),
                               fixed=item['below'], reference='; '.join(item.get('info', [])[:3]),
                               detail=f"Rango: >= {item.get('atOrAbove', '0')}, < {item['below']}. {ids.get('summary', '')}"))
        if product == 'php':
            for advisory in self.source('php_advisories') or []:
                if advisory.get('withdrawn_at'):
                    continue
                for affected in advisory.get('vulnerabilities', []):
                    fixed = str(affected.get('patched_versions') or '').strip()
                    # PHP advisories frequently list '<8.x.y' separately for each branch.
                    if not re.fullmatch(r'\d+\.\d+\.\d+', fixed) or fixed.split('.')[:2] != version.split('.')[:2]:
                        continue
                    try:
                        spec = SpecifierSet(affected.get('vulnerable_version_range', ''))
                        if not str(spec) or current not in spec:
                            continue
                    except (InvalidSpecifier, InvalidVersion):
                        continue
                    issues.append(dict(id=advisory.get('cve_id') or advisory.get('ghsa_id'), kind='advisory',
                                       severity=str(advisory.get('severity', 'medium')).title(), fixed=fixed,
                                       reference=advisory.get('html_url', ''),
                                       detail=f"Rango {spec}; paquete/modulo {affected.get('package', {}).get('name', 'php-src')}. "
                                              f"{advisory.get('summary', '')}. La configuracion y los parches del proveedor requieren validacion."))
                    break
        if product == 'apache-http-server':
            for advisory in self.source('apache_advisories') or []:
                state = (advisory.get('cveMetadata', {}).get('state')
                         or advisory.get('CVE_data_meta', {}).get('STATE'))
                if state and state.upper() not in {'PUBLISHED', 'PUBLIC'}:
                    continue
                cna = advisory.get('containers', {}).get('cna', {})
                identifier = (advisory.get('cveMetadata', {}).get('cveId')
                              or advisory.get('CVE_data_meta', {}).get('ID'))
                matched = False
                for affected in cna.get('affected', []):
                    if affected.get('product') != 'Apache HTTP Server':
                        continue
                    for interval in affected.get('versions', []):
                        if interval.get('status') != 'affected' or interval.get('changes'):
                            continue
                        try:
                            start = Version(interval['version'])
                            if interval.get('lessThan'):
                                matched |= start <= current < Version(interval['lessThan'])
                            elif interval.get('lessThanOrEqual'):
                                matched |= start <= current <= Version(interval['lessThanOrEqual'])
                            else:
                                matched |= start == current
                        except (KeyError, InvalidVersion):
                            continue
                for vendor in advisory.get('affects', {}).get('vendor', {}).get('vendor_data', []):
                    for affected in vendor.get('product', {}).get('product_data', []):
                        if affected.get('product_name') != 'Apache HTTP Server':
                            continue
                        for interval in affected.get('version', {}).get('version_data', []):
                            if isinstance(interval, dict) and interval.get('version_affected') == '=':
                                matched |= interval.get('version_value') == version
                if matched and identifier:
                    level = next((m.get('other', {}).get('content', {}).get('text')
                                  for m in cna.get('metrics', []) if isinstance(m.get('other', {}).get('content'), dict)), None)
                    if not level:
                        level = next((m.get('other') for m in advisory.get('impact', []) if isinstance(m.get('other'), str)), '')
                    severity = {'critical': 'Critical', 'important': 'High', 'moderate': 'Medium', 'low': 'Low'}.get(str(level).lower(), 'Medium')
                    issues.append(dict(id=identifier, kind='advisory', severity=severity,
                                       fixed='una version corregida indicada por Apache',
                                       reference=f'https://httpd.apache.org/security/vulnerabilities_24.html#{identifier}',
                                       detail=f'{cna.get("title") or advisory.get("CVE_data_meta", {}).get("TITLE", "Aviso Apache")}. '
                                              'Coincidencia con rango/entrada del proveedor; validar modulos habilitados, plataforma y backports.'))
        return issues


class VersionAuditor:
    name = 'component_versions'

    def __init__(self, catalog: VersionCatalog) -> None:
        self.catalog = catalog

    async def run(self, ctx: Any) -> list[Any]:
        from modules.common import Finding, run_bounded

        observations = list(getattr(ctx.http, 'version_observations', []))
        for key in ('whatweb_technologies', 'wappy_technologies', 'component_observations'):
            for item in ctx.recon.get(key, []) or []:
                if not isinstance(item, dict):
                    continue
                name = str(item.get('name') or item.get('product') or '').lower()
                product = ALIASES.get(name, name if name in ALIASES.values() else '')
                for version in re.findall(r'\d+(?:\.\d+){1,3}(?:[-+~][A-Za-z0-9._+~-]+)?', str(item.get('version', ''))):
                    if product:
                        observations.append(dict(product=product, version=version, url=item.get('url') or ctx.target.url,
                                                 source=key, evidence=str(item.get('evidence') or item)[:500]))
        for key in ('technologies', 'services', 'ports_services', 'js_libraries'):
            for item in ctx.recon.get(key, []) or []:
                observations.extend(extract_components(str(item), ctx.target.url, key))
        origin = urlsplit(ctx.target.url)
        scripts = []
        for raw in ctx.recon.get('js_libraries', []) or []:
            if not isinstance(raw, str):
                continue
            parsed = urlsplit(raw)
            if ((parsed.scheme, parsed.netloc) == (origin.scheme, origin.netloc)
                    and parsed.path.lower().endswith('.js') and raw not in scripts):
                scripts.append(raw)

        async def script_probe(url: str) -> None:
            if ctx.should_stop():
                return
            response = await ctx.http.request('GET', url, timeout=min(8, ctx.limits.timeout), allow_redirects=False)
            if response and response.status == 200 and 'html' not in str(getattr(response, 'content_type', '')).lower():
                observations.extend(extract_components(response.text, url, 'javascript_content'))

        await run_bounded(scripts[:12], script_probe, limit=3, should_stop=ctx.should_stop)
        inventory: dict[tuple[str, str], list[dict[str, str]]] = {}
        for item in observations[:600]:
            inventory.setdefault((item['product'], item['version']), []).append(item)
        ctx.recon['component_versions'] = [dict(product=p, version=v, observations=items[:12],
                                               assessment='evaluated' if re.fullmatch(r'\d+(?:\.\d+){1,3}', v)
                                               else 'requires_vendor_revision')
                                           for (p, v), items in inventory.items()]
        findings = []
        seen: dict[tuple[str, str], Any] = {}
        for (product, version), items in inventory.items():
            for issue in self.catalog.issues(product, version):
                key = product, issue['id']
                if key in seen:
                    seen[key].details += f' | Otra version afectada observada: {version}; {json.dumps(items[:6], ensure_ascii=False)}'
                    continue
                eol = issue['kind'] == 'eol'
                title = (f'Software sin soporte de seguridad: {product} {issue["cycle"]}' if eol else
                         f'Componente con aviso de seguridad: {product} | {issue["id"]}')
                evidence = (f'Componente={product}; version observada={version}; ID={issue["id"]}; '
                            f'{issue["detail"]}; corregir a={issue["fixed"]}; referencia={issue["reference"]}; '
                            f'fuentes={json.dumps(items[:6], ensure_ascii=False)}; '
                            'Correlacion de version: no demuestra explotacion ni descarta backports o soporte extendido.')
                findings.append(Finding(
                    target=ctx.target.display, category='Componentes/Versiones', severity=issue['severity'],
                    title=title, url=items[0]['url'], endpoint=f'{product}:{issue["id"]}',
                    evidence=evidence, source='version_intelligence', confidence='medium',
                    evidence_strength='moderate', false_positive_risk='medium',
                    cwe='CWE-1104' if eol else 'CWE-1395',
                    cvss=f'{dict(Critical="9.0", High="7.5", Medium="5.3", Low="3.1").get(issue["severity"], "5.3")} (estimado por severidad del aviso)',
                    owasp='A03:2025 - Fallos en la cadena de suministro de software',
                    impact=('Sin actualizaciones de seguridad del proyecto original.' if eol else
                            'La version observada coincide con un rango afectado publicado. El impacto depende de la configuracion y del aviso citado.'),
                    remediation=f'Actualizar {product} a {issue["fixed"]}; comprobar aviso y parches del proveedor. {issue["reference"]}',
                    manual_command=f'{"curl.exe" if os.name == "nt" else "curl"} -k -i --max-time 20 "{items[0]["url"]}"',
                ))
                seen[key] = findings[-1]
        ctx.heartbeat(self.name, f'{len(inventory)} componentes con version; base local con {len(self.catalog.data["sources"])} fuentes', len(inventory), len(findings))
        return findings


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[2]
    database = VersionCatalog(root / 'data' / 'version_catalog.json')
    result = asyncio.run(database.refresh(force=True))
    print(json.dumps(dict(result, diagnostics=database.diagnostics), ensure_ascii=False))
