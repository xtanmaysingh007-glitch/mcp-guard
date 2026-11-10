"""Run the proxy (also `mcp-guard proxy ...` once installed):

    python -m mcp_guard.proxy --policy policy.yaml --user-request-file request.txt \
        [--audit-log audit.jsonl] [--confirm auto|terminal|none] [--prompt-timeout 120] \
        -- <command that starts the real MCP server> [its args...]

The host (Claude Desktop, an IDE, ...) starts THIS command instead of the real server's.
"""
from __future__ import annotations

import argparse
import os
import sys

import anyio
from mcp import Client, StdioServerParameters
from mcp.server.stdio import stdio_server

from .confirm import TerminalConfirm, stderr_note, terminal_available
from .core import GuardedProxy, load_proxy_policy


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="mcp-guard proxy",
        description="Run the guard between an MCP host and a real MCP server. Everything after -- is the real "
                    "server's command; the host starts this command instead of the server's.",
        epilog="example: mcp-guard proxy --policy policy.yaml --user-request-file request.txt "
               "--audit-log audit.jsonl -- python my_server.py   (see docs/proxy.md)")
    ap.add_argument("--policy", required=True, help="policy YAML (start from `mcp-guard init`)")
    ap.add_argument("--user-request-file", required=True,
                    help="text file with the user's current request; re-read on every call")
    ap.add_argument("--audit-log", help="JSON-lines file, one line per decision")
    ap.add_argument("--confirm", choices=["auto", "terminal", "none"], default="auto",
                    help="terminal: ask in the terminal; none: never ask, block; auto: terminal if there is one")
    ap.add_argument("--prompt-timeout", type=float, default=120, help="seconds before an unanswered prompt is a no")
    return ap


def parse(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    ap = build_parser()
    if "--" not in argv:
        ap.parse_args(argv)          # handles --help (and reports missing options) before the error below
        ap.error("put the real server's command after --, e.g. ... -- python my_server.py")
    cut = argv.index("--")
    args, command = ap.parse_args(argv[:cut]), argv[cut + 1:]
    if not command:
        ap.error("no server command after --")
    return args, command


async def serve(args: argparse.Namespace, command: list[str]) -> None:
    confirm_fn = None
    if args.confirm == "terminal" or (args.confirm == "auto" and terminal_available()):
        confirm_fn = TerminalConfirm(timeout=args.prompt_timeout)
    elif args.confirm == "auto":
        stderr_note("no terminal to ask in: untraceable calls will be blocked, not asked")
    policy = load_proxy_policy(args.policy)
    if policy.unknown_tools != "block":
        stderr_note("warning: the policy lets unknown tools run (unknown_tools: allow)")
    # The real server gets our environment (it may need its own API keys); the SDK would pass only a few vars.
    params = StdioServerParameters(command=command[0], args=command[1:], env=dict(os.environ))
    async with Client(params, cache=None) as upstream:       # cache=None: always ask the real server
        proxy = GuardedProxy(policy, upstream, args.user_request_file, args.audit_log, confirm_fn)
        async with stdio_server() as (read, write):
            await proxy.server.run(read, write, proxy.server.create_initialization_options())


def main(argv: list[str] | None = None) -> None:
    args, command = parse(sys.argv[1:] if argv is None else argv)
    anyio.run(serve, args, command)


if __name__ == "__main__":
    main()
