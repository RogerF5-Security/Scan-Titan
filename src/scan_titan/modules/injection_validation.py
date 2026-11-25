"""Independent differential replay gate for internal and external DAST alerts.

Failure to reproduce is INCONCLUSIVE, never evidence that an asset is safe.
Static source/sink co-occurrence is reconnaissance, not executable DOM XSS.
"""
from __future__ import annotations

import base64
import hashlib
import html
import re
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from bs4 import BeautifulSoup, Comment

from finding_triage import injection_family
from .adaptive_guard import AdaptiveResponseGuard


VALIDATION_VERSION = "differential-v1"
DB_ERRORS = re.compile(
    r"SQLSTATE\[[0-9A-Z]{5}\]|\bSQL syntax(?: error)?\b|"
    r"(?:mysql|mysqli|pg)_(?:query|fetch\w*)\s*\(|ORA-\d{4,5}\b|"
    r"unclosed quotation mark after the character string|"
    r"unterminated quoted string at or near|"
    r"(?:sqlite3?\.(?:OperationalError|DatabaseError)|org\.postgresql\.util\.PSQLException)|"
    r"(?:SQLServerException|SqlException):", re.I)


def without_parameter(url: str, param: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode([(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                                                           if k != param]), ""))


def with_parameter(url: str, param: str, payload: str) -> str:
    p = urlsplit(without_parameter(url, param))
    query = parse_qsl(p.query, keep_blank_values=True) + [(param, payload)]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(query), ""))


def comparable(text: str, payloads=()) -> str:
    # Remove reflected inputs before SQL boolean comparisons. Preserve text and
    # DOM structure; size differences alone can never confirm an injection.
    for payload in payloads:
        if payload:
            for variant in (payload, html.escape(payload), urlencode({"v": payload})[2:]):
                text = text.replace(variant, "<INPUT>")
    soup = BeautifulSoup(text[:160000], "html.parser")
    for tag in soup.find_all("input"):
        if str(tag.get("name", "")).lower() in {"csrfmiddlewaretoken", "csrf_token", "_csrf", "nonce"}:
            tag["value"] = "<DYNAMIC>"
    for tag in soup.find_all(True):
        if tag.has_attr("nonce"):
            tag["nonce"] = "<DYNAMIC>"
    return re.sub(r"\s+", " ", str(soup)).strip()


def similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    # Bounded comparison: prevent quadratic work on large minified responses.
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:60000], b[:60000], autojunk=True).ratio()


def unsafe_reflection(response, payload: str) -> str:
    ctype = str(response.content_type).lower().split(";", 1)[0]
    if ctype not in {"text/html", "application/xhtml+xml"} or not payload or payload not in response.text:
        return ""
    soup = BeautifulSoup(response.text, "html.parser")
    spans = [(m.start(), m.end()) for m in re.finditer(re.escape(payload), response.text)]
    line_offsets = [0]
    line_offsets.extend(m.end() for m in re.finditer('\n', response.text))
    # A raw string inside a comment, textarea, JSON, or quoted JS string does
    # not establish executable markup. Require a parsed executable element
    # contributed by this exact payload.
    payload_soup = BeautifulSoup(payload, "html.parser")
    for injected in payload_soup.find_all(True):
        if injected.name not in {"script", "svg", "img", "details", "input", "body", "iframe", "animate", "a"}:
            continue
        for tag in soup.find_all(injected.name):
            line, column = getattr(tag, 'sourceline', None), getattr(tag, 'sourcepos', None)
            if line is None or column is None:
                continue
            offset = line_offsets[line - 1] + column
            if not any(start <= offset < end for start, end in spans):
                continue
            if any(parent.name in {"textarea", "title", "style", "template", "noscript", "xmp"} for parent in tag.parents):
                continue
            supported_events = {'onload', 'onerror', 'ontoggle', 'onbegin', 'onfocus', 'onmouseover', 'onclick',
                                'onanimationstart', 'onanimationend', 'onpointerenter', 'onmouseenter', 'oninput'}
            events = [k for k in injected.attrs if k.lower() in supported_events]
            if any(tag.get(k) == injected.get(k) and str(tag.get(k)).strip() for k in events):
                return f"parsed {tag.name} event handler: {','.join(events)}"
            script_type = str(tag.get('type', '')).lower()
            if (injected.name == "script" and injected.string and tag.string == injected.string
                    and not tag.has_attr('src') and script_type in {'', 'text/javascript', 'application/javascript', 'module'}):
                return "parsed script element with exact payload code"
    return ""


def file_signature(text: str) -> str:
    if re.search(r"(?m)^root:[^:\r\n]*:0:0:[^\r\n]*:[^\r\n]*$", text):
        return "passwd root record"
    if re.search(r"(?im)^\[(?:fonts|extensions|mci extensions)\]\s*$", text) and re.search(r"(?im)^\[(?:files|windows)\]\s*$", text):
        return "win.ini sections"
    for token in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text[:200000]):
        try:
            if base64.b64decode(token, validate=True).lstrip().startswith(b"<?php"):
                return "decoded PHP source"
        except (ValueError, TypeError):
            pass
    return ""


def replay_command(requests: dict[str, str], expected: str, proof: str = "") -> str:
    """PowerShell (5.1 and 7) replay that prints the evidence, not only saves it.

    Each request prints its status line, the lines containing the proof
    (literal match) or the first body lines, and the total time, so control
    and probe can be compared directly in the console.
    """
    def quote(s):
        return "'" + str(s).replace("'", "''") + "'"
    lines = [f"# Scan Titan: reproducir {expected}. Comparar la salida de control y prueba."]
    for label, url in requests.items():
        if label.endswith("_url"):
            label = label[:-4]
        label = re.sub(r"[^a-z0-9_]", "_", label.lower())
        show = (f"$l | Select-String -SimpleMatch {quote(proof)} | Select-Object -First 5; " if proof
                else "$l | Select-Object -First 25; ")
        lines.append(
            f"Write-Host '[{label}]'; "
            f"$l = @(curl.exe -k -sS -i --max-time 30 -w 'ST_TIME=%{{time_total}}s' -- {quote(url)} 2>&1); "
            f"$l[0]; {show}$l | Select-String -SimpleMatch 'ST_TIME='")
    return "\n".join(lines)


def proof_text(family: str, validation: dict, payload: str) -> str:
    """Literal text whose presence in the probe output demonstrates the finding."""
    if family == "xss":
        return str(validation.get("payload") or payload or "")
    if family == "lfi":
        return "root:x:0:0" if "passwd" in str(validation.get("proof", "")) else ""
    if family == "sqli" and validation.get("reason") == "differential_database_error":
        return str(validation.get("proof", ""))[:60]
    return ""


class InjectionValidator:
    def __init__(self):
        self.cache = {}

    async def validate_all(self, ctx, findings):
        for finding in findings:
            family = injection_family(finding)
            if not family:
                continue
            if finding.validation.get("version") == VALIDATION_VERSION:
                continue
            key = (family, finding.url, finding.param, finding.payload, finding.method)
            if key not in self.cache:
                if len(self.cache) >= 120 or ctx.should_stop():
                    verdict = {"state": "INCONCLUSIVE", "reason": "validation_budget_or_stop", "version": VALIDATION_VERSION}
                else:
                    try:
                        verdict = await self.validate(ctx, finding, family)
                    except Exception as exc:
                        verdict = {"state": "INCONCLUSIVE", "reason": "validation_error", "error": str(exc)[:160],
                                   "version": VALIDATION_VERSION}
                self.cache[key] = verdict
            finding.validation = dict(self.cache[key])
            if finding.validation["state"] == "CONFIRMED":
                finding.confidence = "high"
                finding.evidence_strength = "strong"
                finding.false_positive_risk = "low"
                finding.evidence += " | Independent replay: " + str(finding.validation)
                if finding.validation.get("payload") and finding.validation.get("probe_url"):
                    finding.url = finding.validation["probe_url"]
                    finding.payload = finding.validation["payload"]
                finding.title = re.sub(r"\s+candidate(?=:)", "", finding.title, flags=re.I)
                finding.manual_command = replay_command(finding.validation.get("requests", {}),
                                                        finding.validation["reason"],
                                                        proof_text(family, finding.validation, finding.payload))
            else:
                ctx.recon.setdefault("injection_triage", []).append({
                    "title": finding.title, "url": finding.url, "param": finding.param,
                    "source": finding.source, **finding.validation})
            ctx.heartbeat("injection_validation", finding.validation["reason"], len(self.cache), 0)
        return findings

    async def validate(self, ctx, f, family):
        verdict = {"version": VALIDATION_VERSION, "state": "INCONCLUSIVE", "reason": "unsupported_replay"}
        if f.source == "stored_xss" and f.validation.get("proof") == "independent_reload_browser_dialog":
            verdict.update(state="CONFIRMED", reason="browser_execution")
            return verdict
        if (f.method or "GET").upper() != "GET":
            # Stored XSS has its own actual browser execution proof.
            if f.source == "stored_xss" and f.browser_artifact and "execut" in f.evidence.lower():
                verdict.update(state="CONFIRMED", reason="browser_execution")
            return verdict
        p = urlsplit(f.url)
        target = urlsplit(ctx.target.url)
        if (p.scheme, p.netloc) != (target.scheme, target.netloc):
            verdict["reason"] = "out_of_origin_replay"
            return verdict
        param = f.param
        existing = dict(parse_qsl(p.query, keep_blank_values=True))
        if param and param not in existing and f.source.startswith(('zap', 'nuclei')):
            verdict['reason'] = 'non_query_input_requires_original_request'
            return verdict
        # URL is authoritative: do not decode or re-encode an already encoded
        # ZAP attack a second time, or split a SQL pair into a synthetic payload.
        payload = existing.get(param, f.payload) if param else f.payload
        probe_url = f.url if (not param or param in existing) else with_parameter(f.url, param, payload)
        baseline_url = without_parameter(f.url, param) if param else urlunsplit((p.scheme, p.netloc, p.path.rsplit("/", 1)[0] + "/", "", ""))
        verdict["requests"] = {"baseline_url": baseline_url, "probe_url": probe_url}
        baseline = await ctx.http.request("GET", baseline_url, allow_redirects=False)
        probe = await ctx.http.request("GET", probe_url, allow_redirects=False)
        if not baseline or not probe:
            verdict["reason"] = "missing_baseline_or_probe"
            return verdict
        b, v = comparable(baseline.text), comparable(probe.text)
        sim = similarity(b, v)
        verdict.update(similarity=round(sim, 5), baseline_status=baseline.status, probe_status=probe.status,
                       baseline_bytes=baseline.body_len, probe_bytes=probe.body_len,
                       baseline_sha256=hashlib.sha256(baseline.text.encode()).hexdigest(),
                       probe_sha256=hashlib.sha256(probe.text.encode()).hexdigest())
        if AdaptiveResponseGuard.looks_blocked(probe) or AdaptiveResponseGuard.looks_blocked(baseline):
            verdict["reason"] = "waf_or_access_block"
            return verdict
        proof = ""
        if family == "xss":
            proof = unsafe_reflection(probe, payload)
            if proof and payload not in baseline.text:
                # A tiny reflected executable fragment can be <2% of a page.
                # Strong proof takes precedence over the similarity heuristic.
                verdict.update(state="CONFIRMED", reason="unsafe_html_reflection", proof=proof)
                return verdict
            if param:
                # The detector may have picked a payload for the wrong context
                # (attribute breakout reflected as text). Try context payloads;
                # confirmation still requires a parsed executable element.
                escalated = await self.escalate_xss(ctx, f.url, param, baseline)
                if escalated:
                    verdict.update(escalated)
                    verdict["requests"] = {"baseline_url": baseline_url, "probe_url": escalated["probe_url"]}
                    return verdict
        elif family == "lfi":
            proof = file_signature(probe.text)
            if proof and not file_signature(baseline.text):
                repeat = await ctx.http.request("GET", probe_url, allow_redirects=False)
                if repeat and not AdaptiveResponseGuard.looks_blocked(repeat) and file_signature(repeat.text) == proof:
                    verdict.update(state="CONFIRMED", reason="differential_file_content", proof=proof)
                    return verdict
        elif family == "sqli":
            # Do not count database error strings merely echoed from the input.
            body = probe.text.replace(payload, "") if payload else probe.text
            hit = DB_ERRORS.search(body)
            if hit and not DB_ERRORS.search(baseline.text):
                repeat = await ctx.http.request("GET", probe_url, allow_redirects=False)
                if repeat and not AdaptiveResponseGuard.looks_blocked(repeat) and DB_ERRORS.search(repeat.text.replace(payload, "")):
                    verdict.update(state="CONFIRMED", reason="differential_database_error", proof=hit.group()[:200])
                    return verdict
            if param and ("boolean" in f.title.lower() or " / " in f.payload or re.search(r"\b(?:AND|OR)\b.*=", payload, re.I)):
                boolean = await self.boolean(ctx, f, baseline, payload, verdict)
                if boolean:
                    return boolean
            if any(token in (f.title + " " + payload).lower() for token in ("time-based", "time based", "sleep(", "waitfor", "pg_sleep")):
                timed = await self.timing(ctx, payload, baseline_url, probe_url, verdict)
                if timed:
                    return timed
                verdict["reason"] = "timing_not_confirmed"
                return verdict
        # HTTP equivalence alone cannot prove that an input is unkeyed. It is
        # classified as route tolerance only for this reproduced payload.
        if probe.status == baseline.status == 200 and sim > .98 and not proof:
            verdict.update(state="FALSE_POSITIVE", reason="route_tolerance_no_injection_evidence")
        elif not param:
            missing_url = urlunsplit((p.scheme, p.netloc, p.path.rsplit("/", 1)[0] + "/scan_titan_missing_" + hashlib.sha256(f.url.encode()).hexdigest()[:12], "", ""))
            missing = await ctx.http.request("GET", missing_url, allow_redirects=False)
            if missing and missing.status == probe.status and similarity(comparable(missing.text), v) > .98 and not proof:
                verdict.update(state="FALSE_POSITIVE", reason="static_rewrite_catch_all")
        else:
            verdict["reason"] = "no_reproducible_injection_evidence"
        return verdict

    XSS_CONTEXT_PAYLOADS = (
        "<svg onload=alert({m})>",                 # HTML text context
        "\"><svg onload=alert({m})>",              # double-quoted attribute
        "'><svg onload=alert({m})>",               # single-quoted attribute
        "</script><svg onload=alert({m})>",        # inside a script block
        "--><svg onload=alert({m})>",              # inside an HTML comment
        "</textarea><svg onload=alert({m})>",      # inside textarea/title
    )

    async def escalate_xss(self, ctx, url, param, baseline):
        marker = str(int(hashlib.sha256(f"{url}|{param}".encode()).hexdigest()[:8], 16) % 900000 + 100000)
        for template in self.XSS_CONTEXT_PAYLOADS:
            candidate = template.format(m=marker)
            probe_url = with_parameter(url, param, candidate)
            response = await ctx.http.request("GET", probe_url, allow_redirects=False)
            if not response or AdaptiveResponseGuard.looks_blocked(response):
                continue
            proof = unsafe_reflection(response, candidate)
            if not proof or candidate in baseline.text:
                continue
            repeat = await ctx.http.request("GET", probe_url, allow_redirects=False)
            if repeat and unsafe_reflection(repeat, candidate) == proof:
                return {"state": "CONFIRMED", "reason": "unsafe_html_reflection_context_payload", "proof": proof,
                        "payload": candidate, "probe_url": probe_url}
        return None

    async def boolean(self, ctx, f, baseline, payload, verdict):
        pairs = f.payload.split(" / ", 1)
        true = pairs[0] if len(pairs) == 2 else payload
        false = pairs[1] if len(pairs) == 2 else re.sub(r"\b1\s*=\s*1\b", "1=2", true, count=1)
        if true == false:
            return None
        true_url, false_url = with_parameter(f.url, f.param, true), with_parameter(f.url, f.param, false)
        groups = []
        base_url = verdict["requests"]["baseline_url"]
        control = await ctx.http.request("GET", base_url, allow_redirects=False)
        if not control or baseline.status != control.status or similarity(comparable(baseline.text), comparable(control.text)) <= .98:
            verdict["reason"] = "unstable_baseline"
            return None
        for _ in range(2):
            t = await ctx.http.request("GET", true_url, allow_redirects=False)
            f_resp = await ctx.http.request("GET", false_url, allow_redirects=False)
            if not t or not f_resp or any(AdaptiveResponseGuard.looks_blocked(r) for r in (t, f_resp)) or not (t.status == f_resp.status == baseline.status == 200):
                return None
            groups.append((comparable(t.text, (true, false)), comparable(f_resp.text, (true, false))))
        b = comparable(baseline.text, (true, false))
        if all(similarity(b, t) > .98 and similarity(t, f_resp) < .95 for t, f_resp in groups) and all(
            similarity(groups[0][i], groups[1][i]) > .98 for i in (0, 1)):
            verdict.update(state="CONFIRMED", reason="repeatable_boolean_dom_change")
            verdict["requests"] = {"baseline_url": base_url, "true_url": true_url, "false_url": false_url}
            return verdict
        return None

    async def timing(self, ctx, payload, baseline_url, probe_url, verdict):
        match = re.search(r"(?:pg_sleep|sleep)\s*\(\s*(\d+)\s*\)|waitfor\s+delay\s+'0{1,2}:0{1,2}:(\d+)'", payload, re.I)
        delay = int(next((x for x in match.groups() if x), "0")) if match else 0
        if not 5 <= delay <= 10:
            verdict["reason"] = "unsupported_delay_requires_manual_validation"
            return None
        neutral = re.sub(r'((?:pg_sleep|sleep)\s*\(\s*)\d+(\s*\))', r'\g<1>0\2', payload, flags=re.I)
        neutral = re.sub(r"(waitfor\s+delay\s+')0{1,2}:0{1,2}:\d+'", r"\g<1>00:00:00'", neutral, flags=re.I)
        parsed_probe = urlsplit(probe_url)
        query = parse_qsl(parsed_probe.query, keep_blank_values=True)
        neutral_query = [(key, neutral if val == payload else val) for key, val in query]
        neutral_url = urlunsplit((parsed_probe.scheme, parsed_probe.netloc, parsed_probe.path, urlencode(neutral_query), ''))
        if neutral_url == probe_url:
            return None
        verdict['requests']['neutral_url'] = neutral_url
        deltas, controls = [], []
        for index in range(3):
            urls = (baseline_url, probe_url, neutral_url) if index % 2 == 0 else (probe_url, neutral_url, baseline_url)
            responses = [await ctx.http.request("GET", u, allow_redirects=False, timeout=delay + 10) for u in urls]
            if any(r is None or r.status != 200 or AdaptiveResponseGuard.looks_blocked(r) for r in responses):
                return None
            probe_index = 1 if index % 2 == 0 else 0
            control_times = [r.elapsed for i, r in enumerate(responses) if i != probe_index]
            controls.extend(control_times)
            deltas.append(responses[probe_index].elapsed - max(control_times))
        verdict.update(timing_deltas=deltas, control_times=controls)
        if min(deltas) >= max(5.0, delay * .9) and max(controls) - min(controls) < 1.5 and max(deltas) - min(deltas) < 1.5:
            verdict.update(state="CONFIRMED", reason="repeatable_paired_delay")
            return verdict
        return None
