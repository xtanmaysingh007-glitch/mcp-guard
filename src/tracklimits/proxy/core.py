"""The proxy itself: an MCP server to the host, an MCP client to the real server behind it.

    host (Claude Desktop, an IDE, an agent)  <-stdio->  GuardedProxy  <-stdio->  real MCP server

- tools/list is forwarded unchanged. Tool descriptions are the server's text: we pass them on, but they never
  go into the Guard, so whatever they claim ("this address is verified") can't change a decision.
- tools/call goes through Guard.check_call first. Allowed: forwarded with exactly the arguments that were
  checked, and the result is recorded for provenance (trusted or untrusted, per the policy). Blocked or
  declined: never forwarded; the model gets an error result with the reason, so it can tell the user.
- The user's request comes from a file the user writes (never from an MCP tool the model could call). It is
  re-read on every call; when it changes, the Guard starts a new session (new task, fresh provenance).
- Every decision goes to a JSON-lines audit log.

Only the core modules are used (guard, policy, provenance); nothing from the AgentDojo adapter.
"""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path
from typing import Any, Callable

import anyio
import yaml
from mcp import Client, MCPError
from mcp.server import Server, ServerRequestContext
from mcp.types import CallToolRequestParams, CallToolResult, ListToolsResult, PaginatedRequestParams, TextContent

from ..guard import Decision, Guard
from ..policy import Policy


def load_proxy_policy(path: str | Path) -> Policy:
    """The policy, with the proxy's defaults: unknown tools are blocked unless the file says otherwise, and a
    yes covers one exact call (approval scope "call", whatever the file says)."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    policy = Policy.from_yaml(path)
    if "unknown_tools" not in raw:
        policy = policy.with_unknown_tools("block")
    return policy.with_approval_scope("call")


def read_request(path: Path | None) -> str:
    """The user's current request. No file, or an empty one: "" (nothing counts as user-given)."""
    try:
        return path.read_text(encoding="utf-8").strip() if path else ""
    except FileNotFoundError:
        return ""


def result_text(result: CallToolResult) -> str:
    """Everything the model will read from a tool result: text blocks and structured content."""
    parts = [c.text for c in result.content if isinstance(c, TextContent)]
    if result.structured_content is not None:
        parts.append(json.dumps(result.structured_content, ensure_ascii=False, default=str))
    return "\n".join(parts)


class GuardedProxy:
    def __init__(self, policy: Policy, upstream: Client, request_file: str | Path | None,
                 audit_log: str | Path | None = None,
                 confirm_fn: Callable[[str, dict, dict], bool] | None = None):
        """upstream: a connected mcp.Client for the real server. confirm_fn(tool, args, untraceable) -> bool
        asks the user (None = never ask, just block)."""
        self.upstream = upstream
        self.request_file = Path(request_file) if request_file else None
        self.audit_log = Path(audit_log) if audit_log else None
        # reuse_approvals=False: a yes covers the one call the user saw, once (no value scope, no "same call
        # approved earlier"). The prompt's own timeout is the expiry.
        self.guard = Guard(policy, confirm_fn=confirm_fn, reuse_approvals=False)
        self._request: str | None = None      # the request text the current guard session started from
        # One call at a time: the Guard's state (what was seen, what was approved) is not thread-safe, and a
        # result must be recorded before the next call is checked.
        self._lock = anyio.Lock()
        self.server = Server("tracklimits-proxy", on_list_tools=self._list_tools, on_call_tool=self._call_tool)

    async def _list_tools(self, ctx: ServerRequestContext, params: PaginatedRequestParams | None) -> ListToolsResult:
        # Forwarded as is (one page per request; the host follows next_cursor itself).
        return await self.upstream.list_tools(cursor=params.cursor if params else None)

    def _sync_request(self) -> None:
        request = read_request(self.request_file)
        if request != self._request:
            self.guard.start_session(request)
            self._request = request

    def _audit(self, tool: str, args: dict, d: Decision) -> None:
        if not self.audit_log:
            return
        # decision: allowed (clean), approved (asked, yes), declined (asked, no), blocked (never forwarded)
        decision = ("approved" if d.approved else "allowed") if d.allowed else ("declined" if d.asked else "blocked")
        row = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "tool": tool, "args": args, "decision": decision,
               "allowed": d.allowed, "reason": d.reason or "allowed", "asked": d.asked, "approved": d.approved,
               "untraceable": d.tainted, "sources": self.guard.value_sources(tool, args),
               "request_set": bool(self._request)}
        with self.audit_log.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

    async def _call_tool(self, ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
        tool = params.name
        args: dict[str, Any] = copy.deepcopy(dict(params.arguments or {}))
        async with self._lock:
            self._sync_request()
            # The check runs in a worker thread: it may sit in a terminal prompt for a while, and the event
            # loop must keep serving pings meanwhile. The call is HELD until it returns.
            d = await anyio.to_thread.run_sync(self.guard.check_call, tool, args)
            self._audit(tool, args, d)
            if not d.allowed:
                # never forwarded; an error RESULT (not a protocol error), so the model reads the reason
                return CallToolResult(content=[TextContent(type="text", text=d.reason)], is_error=True)
            # forward exactly the arguments that were checked (and, if asked, shown to the user)
            try:
                result = await self.upstream.call_tool(tool, args)
            except MCPError:
                raise                                  # the server's own protocol error, passed through
            # Record what came back (Guard.record_result: an error result is never trusted, even from a trusted
            # tool, and a trusted tool's echo of its own arguments doesn't count).
            # (in a worker thread: a huge output must not stall the event loop, review R8)
            await anyio.to_thread.run_sync(self.guard.record_result, tool, args, result_text(result),
                                           bool(result.is_error))
            return result
