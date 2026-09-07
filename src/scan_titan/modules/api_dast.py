from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

from bs4 import BeautifulSoup

from .common import Finding, ScanContext, VulnerabilityModule, clean_text


class ApiDastModule(VulnerabilityModule):
    name = "api_dast"

    SPEC_PATHS = [
        "/swagger.json",
        "/openapi.json",
        "/api/swagger.json",
        "/api/openapi.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/docs/swagger.json",
        "/swagger/v1/swagger.json",
    ]
    GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql"]
    INTROSPECTION_QUERY = (
        "{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{name kind ofType{name kind}}}}}}}"
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        base = await ctx.http.request("GET", ctx.target.url, allow_redirects=True)
        if not base:
            return findings
        soup = BeautifulSoup(base.text, "html.parser")
        script_urls = self._script_urls(base.final_url, soup)
        if ctx.policy.api_sourcemaps:
            findings.extend(await self._sourcemaps(ctx, script_urls[:35]))
        if ctx.policy.api_openapi:
            findings.extend(await self._openapi(ctx))
        if ctx.policy.api_graphql:
            findings.extend(await self._graphql(ctx))
        self._parameter_mining(ctx, base.text)
        if ctx.policy.api_json_body_tests:
            findings.extend(await self._json_body_reflection_tests(ctx))
        return findings

    async def _openapi(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for idx, path in enumerate(self.SPEC_PATHS, start=1):
            ctx.heartbeat(self.name, f"openapi {path}", idx, len(findings))
            url = urllib.parse.urljoin(ctx.target.url, path)
            result = await ctx.http.request("GET", url, allow_redirects=False)
            if not result or result.status != 200:
                continue
            content_type = result.content_type.lower()
            if "json" not in content_type and not result.text.lstrip().startswith(("{", "[")):
                continue
            spec = self._json(result.text)
            endpoints = self._extract_openapi_endpoints(ctx.target.url, spec)
            if not endpoints:
                continue
            self._merge_endpoints(ctx, endpoints)
            ctx.recon["api_specs"] = sorted(set(ctx.recon.get("api_specs", []) + [url]))
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="API/Recon",
                    severity="Low",
                    title="Public OpenAPI/Swagger specification exposed",
                    url=url,
                    status=str(result.status),
                    evidence=f"Parsed {len(endpoints)} endpoint(s) from API specification.",
                    source=self.name,
                    confidence="high",
                    cwe="CWE-200",
                    owasp="A02:2025 - Configuración de seguridad incorrecta",
                    recommendation="Restrict API documentation in production or sanitize sensitive internal endpoints.",
                )
            )
            break
        return findings

    async def _graphql(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for idx, path in enumerate(self.GRAPHQL_PATHS, start=1):
            ctx.heartbeat(self.name, f"graphql {path}", idx, len(findings))
            url = urllib.parse.urljoin(ctx.target.url, path)
            get_result = await ctx.http.request(
                "GET",
                url,
                params={"query": self.INTROSPECTION_QUERY},
                headers={"Accept": "application/json"},
                allow_redirects=False,
            )
            result = get_result
            if (
                not result
                or result.status not in {200, 400}
                or "__schema" not in result.text
            ) and ctx.policy.allow_state_changing_api_tests:
                result = await ctx.http.request(
                    "POST",
                    url,
                    data=json.dumps({"query": self.INTROSPECTION_QUERY}),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    allow_redirects=False,
                )
            if not result or result.status != 200 or "__schema" not in result.text:
                continue
            schema = self._json(result.text)
            endpoints = self._extract_graphql_fields(ctx.target.url, schema)
            self._merge_endpoints(ctx, endpoints)
            ctx.recon["graphql_endpoints"] = sorted(set(ctx.recon.get("graphql_endpoints", []) + [url]))
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="API/GraphQL",
                    severity="Medium",
                    title="GraphQL introspection enabled",
                    url=url,
                    status=str(result.status),
                    evidence=f"Schema introspection returned {len(endpoints)} field-derived route candidate(s).",
                    source=self.name,
                    confidence="high",
                    cwe="CWE-200",
                    owasp="A02:2025 - Configuración de seguridad incorrecta",
                    recommendation="Disable introspection for public production GraphQL endpoints unless explicitly required.",
                )
            )
            break
        return findings

    async def _sourcemaps(self, ctx: ScanContext, script_urls: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        discovered: list[str] = []
        for idx, script_url in enumerate(script_urls, start=1):
            if not script_url.endswith(".js"):
                continue
            source_map_url = f"{script_url}.map"
            ctx.heartbeat(self.name, f"sourcemap {urllib.parse.urlparse(script_url).path}", idx, len(findings))
            result = await ctx.http.request("GET", source_map_url, allow_redirects=False, timeout=min(ctx.limits.timeout, 8))
            if not result or result.status != 200 or not result.text.lstrip().startswith("{"):
                continue
            data = self._json(result.text)
            endpoints = self._extract_endpoints_from_texts(
                [json.dumps(data.get("sources", [])), *[str(x) for x in data.get("sourcesContent", [])[:30]]],
                ctx.target.url,
                ctx.target.host,
            )
            discovered.extend(endpoints)
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="API/Recon",
                    severity="Low",
                    title="JavaScript source map exposed",
                    url=source_map_url,
                    status=str(result.status),
                    evidence=f"Source map exposed. Extracted {len(endpoints)} route/API candidate(s).",
                    source=self.name,
                    confidence="medium",
                    cwe="CWE-200",
                    owasp="A02:2025 - Configuración de seguridad incorrecta",
                    recommendation="Avoid publishing production source maps when they expose internal routes or source code.",
                )
            )
        if discovered:
            self._merge_endpoints(ctx, [{"url": item, "params": self._params(item), "method": "GET"} for item in discovered])
            ctx.recon["sourcemap_routes"] = sorted(set(ctx.recon.get("sourcemap_routes", []) + discovered))[:500]
        return findings

    def _parameter_mining(self, ctx: ScanContext, html: str) -> None:
        existing = list(ctx.recon.get("endpoints", []))
        mined: list[dict[str, Any]] = []
        patterns = [
            r"[?&]([A-Za-z0-9_]{2,40})=",
            r"['\"]([A-Za-z0-9_]*(?:id|user|token|file|path|url|query|search|redirect|next)[A-Za-z0-9_]*)['\"]\s*:",
            r"(?:params|query|body)\.([A-Za-z0-9_]{2,40})",
        ]
        params = sorted({match for pattern in patterns for match in re.findall(pattern, html, flags=re.IGNORECASE)})[:80]
        if params:
            mined.append({"url": ctx.target.url, "params": params, "method": "GET", "source": "parameter_mining"})
        for item in existing[:120]:
            url = item.get("url") if isinstance(item, dict) else ""
            if not url:
                continue
            merged_params = sorted(set((item.get("params") or []) + params[:12]))
            if merged_params:
                item["params"] = merged_params
        if mined:
            self._merge_endpoints(ctx, mined)
            ctx.recon["mined_parameters"] = params

    async def _json_body_reflection_tests(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.policy.allow_state_changing_api_tests:
            return []
        findings: list[Finding] = []
        candidates = [
            item
            for item in ctx.recon.get("endpoints", [])[:80]
            if isinstance(item, dict) and str(item.get("method", "GET")).upper() in {"POST", "PUT", "PATCH"}
        ]
        marker = "scan_titan_json_marker"
        for idx, item in enumerate(candidates[:12], start=1):
            url = item.get("url")
            body_params = item.get("body_params") or ["name", "title", "query"]
            if not url:
                continue
            payload = {str(name): marker for name in body_params[:8]}
            ctx.heartbeat(self.name, f"json-body {urllib.parse.urlparse(url).path}", idx, len(findings))
            result = await ctx.http.request(
                str(item.get("method", "POST")).upper(),
                url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json", "Accept": "application/json,text/html"},
                allow_redirects=False,
            )
            if result and marker in result.text:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="API/DAST",
                        severity="Medium",
                        title="JSON body reflection candidate",
                        url=url,
                        method=str(item.get("method", "POST")).upper(),
                        payload=json.dumps(payload),
                        status=str(result.status),
                        evidence="JSON marker reflected in response body.",
                        source=self.name,
                        confidence="medium",
                        cwe="CWE-79",
                        owasp="A05:2025 - Inyección",
                        recommendation="Validate and encode JSON body values before rendering them in responses.",
                    )
                )
        return findings

    def _extract_openapi_endpoints(self, base_url: str, spec: dict[str, Any]) -> list[dict[str, Any]]:
        endpoints: list[dict[str, Any]] = []
        paths = spec.get("paths", {})
        if not isinstance(paths, dict):
            return endpoints
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, meta in methods.items():
                method_upper = str(method).upper()
                if method_upper not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                    continue
                params = []
                body_params = []
                if isinstance(meta, dict):
                    for param in meta.get("parameters", []) or []:
                        if isinstance(param, dict) and param.get("name"):
                            params.append(str(param["name"]))
                    body_params.extend(self._request_body_fields(meta.get("requestBody", {})))
                clean_path = re.sub(r"\{([^}]+)\}", "1", str(path))
                endpoints.append(
                    {
                        "url": urllib.parse.urljoin(base_url, clean_path),
                        "params": sorted(set(params)),
                        "body_params": sorted(set(body_params)),
                        "method": method_upper,
                        "source": "openapi",
                    }
                )
        return endpoints[:700]

    def _request_body_fields(self, request_body: Any) -> list[str]:
        if not isinstance(request_body, dict):
            return []
        content = request_body.get("content", {})
        fields: list[str] = []
        if isinstance(content, dict):
            for media_meta in content.values():
                schema = media_meta.get("schema", {}) if isinstance(media_meta, dict) else {}
                fields.extend(self._schema_fields(schema))
        return fields

    def _schema_fields(self, schema: Any) -> list[str]:
        if not isinstance(schema, dict):
            return []
        props = schema.get("properties", {})
        fields = [str(key) for key in props.keys()] if isinstance(props, dict) else []
        for key in ("allOf", "oneOf", "anyOf"):
            for item in schema.get(key, []) or []:
                fields.extend(self._schema_fields(item))
        return fields[:60]

    def _extract_graphql_fields(self, base_url: str, schema: dict[str, Any]) -> list[dict[str, Any]]:
        data = schema.get("data", {}) if isinstance(schema, dict) else {}
        types = data.get("__schema", {}).get("types", []) if isinstance(data, dict) else []
        endpoints: list[dict[str, Any]] = []
        for item in types:
            if not isinstance(item, dict) or item.get("kind") not in {"OBJECT", "INTERFACE"}:
                continue
            for field in item.get("fields", []) or []:
                if not isinstance(field, dict) or not field.get("name"):
                    continue
                params = [str(arg.get("name")) for arg in field.get("args", []) or [] if isinstance(arg, dict) and arg.get("name")]
                endpoints.append(
                    {
                        "url": urllib.parse.urljoin(base_url, "/graphql"),
                        "params": params,
                        "method": "POST",
                        "graphql_field": field.get("name"),
                        "source": "graphql",
                    }
                )
        return endpoints[:250]

    def _extract_endpoints_from_texts(self, texts: list[str], base_url: str, host: str) -> list[str]:
        out = set()
        patterns = [
            r"""["'`]((?:/|\.\./|\./)(?:api|rest|graphql|oauth|admin|login|user|basket|profile|order|account)[^"'`<>\s]{0,180})["'`]""",
            r"""https?://[^"'`<>\s]+""",
        ]
        for text in texts:
            for pattern in patterns:
                for raw in re.findall(pattern, text, flags=re.IGNORECASE):
                    full = urllib.parse.urljoin(base_url, str(raw).replace("\\/", "/"))
                    parsed = urllib.parse.urlparse(full)
                    if parsed.hostname and parsed.hostname == host:
                        out.add(parsed.geturl())
        return sorted(out)[:500]

    def _script_urls(self, base_url: str, soup: Any) -> list[str]:
        urls = []
        for script in soup.find_all("script", src=True):
            src = urllib.parse.urljoin(base_url, script.get("src"))
            if src and src not in urls:
                urls.append(src)
        return urls

    def _merge_endpoints(self, ctx: ScanContext, endpoints: list[dict[str, Any]]) -> None:
        current = list(ctx.recon.get("endpoints", []))
        seen = {item.get("url") + "|" + str(item.get("method", "GET")) for item in current if isinstance(item, dict) and item.get("url")}
        for endpoint in endpoints:
            url = endpoint.get("url")
            if not url:
                continue
            key = url + "|" + str(endpoint.get("method", "GET"))
            if key in seen:
                continue
            current.append(endpoint)
            seen.add(key)
        ctx.recon["endpoints"] = current[:1000]
        discovered = list(ctx.recon.get("discovered_paths", []))
        for endpoint in endpoints:
            url = endpoint.get("url")
            if url:
                discovered.append(urllib.parse.urlparse(url).path or url)
        ctx.recon["discovered_paths"] = sorted(set(discovered))[:1000]

    def _params(self, url: str) -> list[str]:
        return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())

    def _json(self, text: str) -> dict[str, Any]:
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
