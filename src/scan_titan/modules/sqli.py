from __future__ import annotations

import asyncio
import urllib.parse

from .common import Finding, ScanContext, VulnerabilityModule, clean_text, url_with_params
from .payload_utils import sqli_payloads


class SqliModule(VulnerabilityModule):
    name = "sqli"
    MAX_ERROR_PROBES = 1400
    MAX_ERROR_PROBES_FULL = 2400
    MAX_CANDIDATE_PAIRS = 36
    MAX_CANDIDATE_PAIRS_FULL = 60

    DEFAULT_PARAMS = [
        "id",
        "uid",
        "user",
        "username",
        "search",
        "query",
        "page",
        "category",
        "item",
        "product",
        "order",
        "sort",
    ]

    ERROR_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "'/**/OR/**/'1'='1",
        "1' OR '1'='1'--",
        "' UNION SELECT NULL--",
        "\") OR (\"1\"=\"1",
    ]

    BOOLEAN_PAIRS = [
        ("1 AND 1=1", "1 AND 1=2"),
        ("' AND 'a'='a", "' AND 'a'='b"),
        ("1/**/AND/**/1=1", "1/**/AND/**/1=2"),
    ]

    DB_ERRORS = [
        "sql syntax",
        "mysql_fetch",
        "mysqli_fetch",
        "warning: mysql",
        "you have an error in your sql",
        "postgresql",
        "pg_query",
        "sqlite_",
        "ora-",
        "oracle error",
        "odbc",
        "sqlstate",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "unterminated quoted string",
        "syntax error",
        "mssql",
        "sqlexception",
    ]

    HIGH_VALUE_PARAMS = {
        "id",
        "uid",
        "user",
        "username",
        "email",
        "login",
        "search",
        "query",
        "q",
        "page",
        "category",
        "item",
        "product",
        "order",
        "sort",
        "filter",
        "where",
    }

    HIGH_VALUE_URL_TOKENS = (
        "login",
        "auth",
        "api",
        "search",
        "query",
        "user",
        "admin",
        "product",
        "item",
        "order",
        "report",
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        max_tests = max(1, int(ctx.limits.max_tests_per_module))
        budget = self._effective_budget(max_tests)
        payloads = self._prioritize_payloads(sqli_payloads(ctx.wordlists, self.ERROR_PAYLOADS, limit=budget))
        candidates = self._candidate_urls(ctx)
        candidate_pairs = self._candidate_pairs(candidates, max_tests)
        findings: list[Finding] = []
        tested = 0
        lock = asyncio.Lock()
        found_pairs: set[tuple[str, str]] = set()
        error_budget = min(budget, max(1, int(max_tests * 0.72)))
        probe_specs = self._build_probe_plan(candidate_pairs, payloads, error_budget)
        baselines: dict[tuple[str, str], object | None] = {}
        for url, param in dict.fromkeys((url, param) for url, param, _payload in probe_specs):
            baselines[(url, param)] = await ctx.http.request(
                "GET", url, params={param: "scan_titan_control"}, timeout=min(ctx.limits.timeout, 6)
            )

        async def error_probe(url: str, param: str, payload: str, baseline: object | None) -> None:
            nonlocal tested
            pair = (url, param)
            if pair in found_pairs:
                return
            async with lock:
                tested += 1
                if tested == 1 or tested % 20 == 0:
                    ctx.heartbeat(self.name, f"error {param}={payload[:26]}", tested, len(findings))
            result = await ctx.http.request("GET", url, params={param: payload}, timeout=min(ctx.limits.timeout, 6))
            if not result:
                return
            lower = result.text.lower()
            baseline_lower = str(getattr(baseline, "text", "") or "").lower()
            hit = next(
                (item for item in self.DB_ERRORS if item in lower and item not in baseline_lower),
                None,
            )
            if not hit:
                return
            async with lock:
                if pair in found_pairs:
                    return
                found_pairs.add(pair)
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="SQLi",
                        severity="Critical",
                        title=f"SQL Injection error-based: {param}",
                        url=url_with_params(url, {param: payload}),
                        endpoint=urllib.parse.urlparse(url).path or "/",
                        param=param,
                        method="GET",
                        payload=payload,
                        status=str(result.status),
                        size=f"{result.body_len}b",
                        elapsed=f"{result.elapsed:.2f}s",
                        evidence=f"Differential database error signature observed only after payload: {hit}",
                        source=self.name,
                        confidence="high",
                        evidence_strength="strong",
                        false_positive_risk="low",
                    )
                )

        for batch in self._chunks(probe_specs, max(4, min(32, int(ctx.limits.throttle_batch_size or 8) * 2))):
            await asyncio.gather(
                *[
                    error_probe(url, param, payload, baselines.get((url, param)))
                    for url, param, payload in batch
                ]
            )
        findings.extend(await self._boolean_differential(ctx, candidates, len(probe_specs), len(findings)))
        return findings

    async def _boolean_differential(
        self,
        ctx: ScanContext,
        candidates: list[tuple[str, list[str]]],
        tested_offset: int,
        found_offset: int,
    ) -> list[Finding]:
        findings: list[Finding] = []
        tested = tested_offset
        max_tests = max(1, int(ctx.limits.max_tests_per_module))
        for url, params in candidates[:8]:
            for param in params[:6]:
                if tested + 2 > max_tests:
                    return findings
                baseline = await ctx.http.request("GET", url, params={param: "scan_titan_control"}, timeout=min(ctx.limits.timeout, 6))
                if not baseline:
                    continue
                for true_payload, false_payload in self.BOOLEAN_PAIRS:
                    if tested + 2 > max_tests:
                        return findings
                    tested += 2
                    ctx.heartbeat(self.name, f"boolean {param}", tested, found_offset + len(findings))
                    true_resp, false_resp = await asyncio.gather(
                        ctx.http.request("GET", url, params={param: true_payload}, timeout=min(ctx.limits.timeout, 6)),
                        ctx.http.request("GET", url, params={param: false_payload}, timeout=min(ctx.limits.timeout, 6)),
                    )
                    if not true_resp or not false_resp:
                        continue
                    true_delta = abs(true_resp.body_len - baseline.body_len)
                    false_delta = abs(false_resp.body_len - baseline.body_len)
                    diff = abs(true_resp.body_len - false_resp.body_len)
                    if true_resp.status == false_resp.status and diff > 120 and false_delta > true_delta + 80:
                        if tested + 2 > max_tests:
                            return findings
                        tested += 2
                        ctx.heartbeat(self.name, f"boolean confirm {param}", tested, found_offset + len(findings))
                        confirm_true, confirm_false = await asyncio.gather(
                            ctx.http.request("GET", url, params={param: true_payload}, timeout=min(ctx.limits.timeout, 6)),
                            ctx.http.request("GET", url, params={param: false_payload}, timeout=min(ctx.limits.timeout, 6)),
                        )
                        if not confirm_true or not confirm_false:
                            continue
                        confirm_diff = abs(confirm_true.body_len - confirm_false.body_len)
                        stable_true = abs(confirm_true.body_len - true_resp.body_len) <= 60
                        stable_false = abs(confirm_false.body_len - false_resp.body_len) <= 60
                        if (
                            confirm_true.status != confirm_false.status
                            or confirm_diff <= 120
                            or not stable_true
                            or not stable_false
                        ):
                            continue
                        findings.append(
                            Finding(
                                target=ctx.target.display,
                                category="SQLi",
                                severity="High",
                                title=f"SQL Injection boolean differential: {param}",
                                url=url_with_params(url, {param: true_payload}),
                                endpoint=urllib.parse.urlparse(url).path or "/",
                                param=param,
                                method="GET",
                                payload=f"{true_payload} / {false_payload}",
                                status=str(true_resp.status),
                                size=f"true={true_resp.body_len}b false={false_resp.body_len}b",
                                elapsed=f"{max(true_resp.elapsed, false_resp.elapsed):.2f}s",
                                evidence=clean_text(
                                    f"Baseline={baseline.body_len} | True={true_resp.body_len} | "
                                    f"False={false_resp.body_len} | Diff={diff} | "
                                    f"ConfirmTrue={confirm_true.body_len} | ConfirmFalse={confirm_false.body_len}",
                                    300,
                                ),
                                source=self.name,
                                confidence="high",
                                evidence_strength="strong",
                                false_positive_risk="low",
                            )
                        )
                        break
        return findings

    def _effective_budget(self, max_tests: int) -> int:
        if max_tests >= 50_000:
            return min(max_tests, self.MAX_ERROR_PROBES_FULL)
        return min(max_tests, self.MAX_ERROR_PROBES)

    def _prioritize_payloads(self, payloads: list[str]) -> list[str]:
        def score(payload: str) -> tuple[int, int]:
            text = payload.lower()
            points = 0
            if any(token in text for token in ("'", '"', " or ", " and ", "union", "select", "sleep", "benchmark")):
                points -= 8
            if any(token in text for token in ("drop ", "delete ", "insert ", "update ")):
                points += 50
            if len(payload) > 180:
                points += 5
            return points, len(payload)

        return sorted(dict.fromkeys(payloads), key=score)

    def _candidate_pairs(self, candidates: list[tuple[str, list[str]]], max_tests: int) -> list[tuple[str, str]]:
        limit = self.MAX_CANDIDATE_PAIRS_FULL if max_tests >= 50_000 else self.MAX_CANDIDATE_PAIRS
        pairs: list[tuple[str, str]] = []
        for url, params in sorted(candidates, key=self._candidate_score):
            for param in sorted(dict.fromkeys(params), key=self._param_score):
                pair = (url, param)
                if pair not in pairs:
                    pairs.append(pair)
                if len(pairs) >= limit:
                    return pairs
        return pairs

    def _candidate_score(self, item: tuple[str, list[str]]) -> tuple[int, str]:
        url, params = item
        lower = url.lower()
        score = 0
        if urllib.parse.urlparse(url).query:
            score -= 10
        if any(token in lower for token in self.HIGH_VALUE_URL_TOKENS):
            score -= 8
        if any(str(param).lower() in self.HIGH_VALUE_PARAMS for param in params):
            score -= 5
        return score, url

    def _param_score(self, param: str) -> tuple[int, str]:
        lower = str(param or "").lower()
        score = 0 if lower in self.HIGH_VALUE_PARAMS else 10
        if any(token in lower for token in ("id", "user", "search", "query", "filter", "order")):
            score -= 5
        return score, lower

    def _build_probe_plan(
        self,
        pairs: list[tuple[str, str]],
        payloads: list[str],
        budget: int,
    ) -> list[tuple[str, str, str]]:
        if not pairs or not payloads or budget <= 0:
            return []
        per_pair = min(len(payloads), max(6, max(1, budget // len(pairs))))
        specs: list[tuple[str, str, str]] = []
        for payload_index in range(per_pair):
            for url, param in pairs:
                if len(specs) >= budget:
                    return specs
                specs.append((url, param, payloads[payload_index]))
        return specs

    @staticmethod
    def _chunks(items: list[tuple[str, str, str]], size: int) -> list[list[tuple[str, str, str]]]:
        return [items[index:index + size] for index in range(0, len(items), max(1, size))]

    def _candidate_urls(self, ctx: ScanContext) -> list[tuple[str, list[str]]]:
        candidates = [(ctx.target.url, self.DEFAULT_PARAMS)]
        for endpoint in ctx.recon.get("endpoints", [])[:40]:
            url = endpoint.get("url")
            params = endpoint.get("params") or []
            if url:
                candidates.append((url, params or self.DEFAULT_PARAMS[:6]))
        seen = set()
        unique = []
        for url, params in candidates:
            key = (url, ",".join(sorted(params)))
            if key not in seen:
                seen.add(key)
                unique.append((url, params))
        return unique
