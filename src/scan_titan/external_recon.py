"""Bounded adapters for passive, same-origin external reconnaissance."""

from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from collections.abc import Awaitable, Callable
from typing import Any


CommandResult = tuple[str, str, bool, int | None, float]
CommandRunner = Callable[[list[str], int], Awaitable[CommandResult]]


class ExternalCommandQueue:
    """Keep a small queue and one subprocess active per target."""

    def __init__(self, runner: CommandRunner, max_pending: int = 2) -> None:
        self._runner = runner
        self._queue: asyncio.Queue[
            tuple[list[str], int, asyncio.Future[CommandResult]] | None
        ] = asyncio.Queue(maxsize=max(1, max_pending))
        self._worker: asyncio.Task[None] | None = None

    async def run(self, command: list[str], timeout: int) -> CommandResult:
        if self._worker is None:
            self._worker = asyncio.create_task(self._drain())
        future: asyncio.Future[CommandResult] = asyncio.get_running_loop().create_future()
        await self._queue.put((command, timeout, future))
        try:
            return await future
        except asyncio.CancelledError:
            future.cancel()
            if self._worker and not self._worker.done():
                self._worker.cancel()
                await asyncio.gather(self._worker, return_exceptions=True)
            raise

    async def close(self) -> None:
        if self._worker is not None:
            if not self._worker.done():
                await self._queue.put(None)
            await asyncio.gather(self._worker, return_exceptions=True)
            self._worker = None

    async def _drain(self) -> None:
        try:
            while True:
                job = await self._queue.get()
                try:
                    if job is None:
                        return
                    command, timeout, future = job
                    if future.cancelled():
                        continue
                    try:
                        result = await self._runner(command, timeout)
                    except Exception as exc:
                        if not future.done():
                            future.set_exception(exc)
                    else:
                        if not future.done():
                            future.set_result(result)
                finally:
                    self._queue.task_done()
        finally:
            while not self._queue.empty():
                job = self._queue.get_nowait()
                if job is not None and not job[2].done():
                    job[2].cancel()
                self._queue.task_done()


def same_origin_url(value: str, origin: str) -> str | None:
    """Accept only HTTP URLs for the exact configured scheme, host and port."""
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 32 for c in value):
        return None
    try:
        candidate = urllib.parse.urlsplit(value.strip())
        root = urllib.parse.urlsplit(origin)
        if candidate.scheme not in {"http", "https"} or candidate.scheme != root.scheme:
            return None
        if candidate.username or candidate.password or candidate.hostname != root.hostname:
            return None
        default = {"http": 80, "https": 443}
        if (candidate.port or default[candidate.scheme]) != (root.port or default[root.scheme]):
            return None
    except ValueError:
        return None
    return urllib.parse.urlunsplit(
        (candidate.scheme, candidate.netloc, candidate.path or "/", candidate.query, "")
    )


def parse_katana(output: str, origin: str, limit: int = 300) -> list[dict[str, Any]]:
    """Read JSONL or plain Katana URLs without trusting off-scope results."""
    found: dict[str, dict[str, Any]] = {}
    for line in output.splitlines():
        if len(found) >= limit:
            break
        try:
            item: Any = json.loads(line)
        except (ValueError, TypeError):
            item = line.strip()
        if isinstance(item, dict):
            raw = item.get("request", {}).get("endpoint") if isinstance(item.get("request"), dict) else None
            raw = raw or item.get("url") or item.get("endpoint")
        else:
            raw = item
        url = same_origin_url(raw, origin)
        if not url:
            continue
        params = list(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).keys())
        found.setdefault(url, {"url": url, "params": params, "source": "katana"})
    return list(found.values())


def parse_projectdiscovery_httpx(output: str, origin: str) -> list[dict[str, Any]]:
    """Keep HTTP metadata as reconnaissance, never as a confirmed finding."""
    records: list[dict[str, Any]] = []
    for line in output.splitlines()[:20]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        url = same_origin_url(str(item.get("url") or ""), origin)
        if not url:
            continue
        technologies = item.get("tech") or []
        if not isinstance(technologies, list):
            technologies = []
        records.append({
            "url": url,
            "status_code": item.get("status_code"),
            "title": str(item.get("title") or "")[:160],
            "webserver": str(item.get("webserver") or "")[:160],
            "technologies": [str(value)[:100] for value in technologies[:30]],
        })
    return records


def is_projectdiscovery_httpx_help(output: str) -> bool:
    """Reject the unrelated Python httpx command that often wins on Windows PATH."""
    lower = output.lower()
    return "-tech-detect" in lower and "-status-code" in lower and "-json" in lower


def katana_command(binary: str, url: str, output: str, timeout: int) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    scope = r"^" + re.escape(f"{parsed.scheme}://{parsed.netloc}") + r"(?:/|$)"
    return [
        binary, "-u", url, "-d", "2", "-ct", f"{max(1, timeout // 60)}m",
        "-c", "1", "-p", "1", "-rl", "2", "-timeout", "8",
        "-cs", scope, "-dr", "-or", "-ob", "-jsonl", "-silent", "-o", output,
    ]


def httpx_command(binary: str, url: str, output: str) -> list[str]:
    return [
        binary, "-u", url, "-sc", "-title", "-server", "-td", "-ip",
        "-cdn", "-json", "-silent", "-duc", "-t", "1", "-rl", "2",
        "-timeout", "8", "-retries", "0", "-o", output,
    ]
