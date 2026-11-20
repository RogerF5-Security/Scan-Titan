"""Bounded same-origin JavaScript inventory; indicators are never vulnerabilities."""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from bs4 import BeautifulSoup


def analyze_javascript(source: str, text: str, origin: str) -> dict:
    endpoints = []
    patterns = [r"(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['\"]([^'\"\s]{1,500})",
                r"(?:url|endpoint|baseURL)\s*:\s*['\"]([^'\"\s]{1,500})",
                r"['\"](/(?:api|graphql|rest|auth|admin|v[1-9])[^'\"\s]{0,300})['\"]"]
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            literal = match.group(1)
            if "${" in literal:
                continue
            url = urljoin(source, literal)
            if urlsplit(url).scheme not in {"http", "https"}:
                continue
            endpoints.append({"url": url, "source": source, "line": text.count("\n", 0, match.start()) + 1,
                              "in_scope": (urlsplit(url).scheme, urlsplit(url).netloc) == (urlsplit(origin).scheme, urlsplit(origin).netloc),
                              "params": [k for k, _ in parse_qsl(urlsplit(url).query)]})
    imports = re.findall(r"(?:import\s*\(\s*|from\s*|import\s*)['\"]([^'\"]+\.(?:js|mjs)(?:\?[^'\"]*)?)['\"]", text)
    maps = re.findall(r"[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)", text)
    flows = []
    for match in re.finditer(r"(?:innerHTML|outerHTML)\s*=\s*[^;\n]{0,200}(?:location\.(?:search|hash)|document\.(?:URL|referrer))|"
                             r"(?:eval|document\.write|insertAdjacentHTML)\s*\([^;\n]{0,200}(?:location\.(?:search|hash)|document\.(?:URL|referrer))", text):
        flows.append({"source": source, "line": text.count("\n", 0, match.start()) + 1,
                      "snippet": match.group()[:320], "state": "STATIC_CANDIDATE_REQUIRES_BROWSER"})
    secrets = []
    for label, pattern in {
        "AWS access key identifier": r"AKIA[0-9A-Z]{16}",
        "GitHub token candidate": r"ghp_[A-Za-z0-9]{36}",
        "JWT candidate": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "Private key material": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "API credential candidate": r"(?:api_key|apikey|client_secret)\s*[:=]\s*['\"][A-Za-z0-9_/-]{20,100}['\"]",
    }.items():
        for match in re.finditer(pattern, text):
            secrets.append({"type": label, "source": source, "line": text.count("\n", 0, match.start()) + 1,
                            "redacted": match.group()[:4] + "…[redacted]",
                            "sha256": hashlib.sha256(match.group().encode()).hexdigest(),
                            "state": "UNVERIFIED_CREDENTIAL"})
    storage = sorted(set(re.findall(r"(?:localStorage|sessionStorage)\.(?:getItem|setItem)\(['\"]([^'\"]{1,80})", text)))
    unique = {item["url"]: item for item in endpoints}
    return {"source": source, "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "endpoints": list(unique.values())[:200], "imports": imports[:60], "source_maps": maps[:8],
            "dom_flows": flows[:30], "secret_candidates": secrets[:30], "storage_keys": storage[:40]}


async def javascript_recon(ctx, response):
    soup = BeautifulSoup(response.text, "html.parser")
    origin = urlsplit(ctx.target.url)
    inventory = {"scripts": [], "endpoints": [], "source_maps": [], "dom_flows": [],
                 "secret_candidates": [], "storage_keys": [], "coverage": [], "limits": {"scripts": 40, "maps": 4, "characters_per_script": 500000}}
    ctx.recon["javascript_recon"] = inventory
    queue = [urljoin(response.final_url, tag["src"]) for tag in soup.find_all("script", src=True)]
    sources = [(response.final_url, "\n".join(tag.string or tag.get_text() for tag in soup.find_all("script", src=False)))]
    seen = set()
    map_count = 0
    while sources or queue:
        if ctx.should_stop():
            inventory["coverage"].append({"state": "stopped"})
            break
        if sources:
            source, text = sources.pop(0)
        else:
            source = queue.pop(0)
            parsed = urlsplit(source)
            if source in seen:
                continue
            if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc):
                inventory["coverage"].append({"source": source, "state": "external_not_fetched"})
                seen.add(source)
                continue
            if len(inventory["scripts"]) >= 40:
                inventory["coverage"].append({"state": "script_budget", "pending": len(queue) + 1})
                break
            seen.add(source)
            result = await ctx.http.request("GET", source, allow_redirects=False)
            if not result or result.status != 200 or "html" in result.content_type.lower():
                inventory["coverage"].append({"source": source, "state": "unavailable_or_not_javascript"})
                continue
            text = result.text
        truncated = len(text) > 500000
        info = analyze_javascript(source, text[:500000], ctx.target.url)
        inventory["scripts"].append({"url": source, "sha256": info["sha256"], "characters": len(text), "truncated": truncated})
        for field in ("endpoints", "dom_flows", "secret_candidates", "storage_keys"):
            inventory[field].extend(info[field])
        queue.extend(urljoin(source, item) for item in info["imports"])
        for map_ref in info["source_maps"]:
            if map_ref.startswith('data:'):
                inventory['source_maps'].append({'source': source, 'state': 'inline_map_not_fetched', 'url': '[inline map]'})
                continue
            map_url = urljoin(source, map_ref)
            item = {"url": map_url, "source": source, "state": "referenced"}
            if map_count < 4 and (urlsplit(map_url).scheme, urlsplit(map_url).netloc) == (origin.scheme, origin.netloc) and not map_ref.startswith("data:"):
                map_count += 1
                result = await ctx.http.request("GET", map_url, allow_redirects=False)
                if result and result.status == 200 and len(result.text) <= 1000000:
                    try:
                        parsed_map = json.loads(result.text)
                        if parsed_map.get("version") == 3 and isinstance(parsed_map.get("sources"), list):
                            item.update(state="valid_source_map", files=parsed_map["sources"][:100],
                                        embedded_sources=sum(bool(x) for x in parsed_map.get("sourcesContent", [])))
                            for index, code in enumerate(parsed_map.get("sourcesContent", [])[:20]):
                                if isinstance(code, str):
                                    embedded = analyze_javascript(map_url + "#source=" + str(index), code[:100000], ctx.target.url)
                                    for field in ("endpoints", "dom_flows", "secret_candidates", "storage_keys"):
                                        inventory[field].extend(embedded[field])
                    except (ValueError, AttributeError, TypeError):
                        item["state"] = "not_a_valid_map"
            inventory["source_maps"].append(item)
        ctx.heartbeat("javascript_recon", source, len(inventory["scripts"]), len(inventory["endpoints"]))
    inventory["storage_keys"] = sorted(set(inventory["storage_keys"]))[:200]
    inventory["endpoints"] = list({item["url"]: item for item in inventory["endpoints"]}.values())[:500]
    ctx.recon["javascript_recon"] = inventory
    for endpoint in inventory["endpoints"]:
        if endpoint["in_scope"]:
            ctx.recon.setdefault("endpoints", []).append({"url": endpoint["url"], "params": endpoint["params"], "source": "javascript_static"})
    return inventory
