"""`tracklimits init`: write a policy skeleton for a set of tools.

Input: a JSON file with an MCP server's tool list. Accepted shapes: the tools/list result
({"tools": [...]}), the whole JSON-RPC response ({"result": {"tools": [...]}}), a plain list of tool
objects, or a plain list of names.

Output: a YAML policy where EVERY tool sits under "unclassified" and unknown_tools is "block". So nothing
runs until a person has looked at each tool and moved it into a section. Each section is explained in
comments. The file loads as a valid Policy as is (it just blocks everything).

    python -m tracklimits init tools.json -o policy.yaml [--force]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HEADER = """\
# TrackLimits policy (skeleton made by `tracklimits init`).
#
# Every tool starts under "unclassified" at the bottom, and unknown_tools is "block": a tool that is in no
# section below can't run. Move each tool into the section(s) that fit, then delete it from "unclassified".
#
# trusted_tools: tools whose OUTPUT is structured data the user owns (their own account, the clock). Whole
#   values from them count as traceable. Add weak_trusted_tools for trusted tools an attacker can write into
#   (contact lists built from incoming mail, channel names anyone can set).
# safe_tools: read-only tools with nothing to guard (search, list, read). They run; their output is still
#   untrusted data.
# forbid_tainted: tool -> arguments that must trace to the user's request or a trusted tool (recipients,
#   payees, URLs, file shares). Anything else in them is blocked (or asked about, if confirmable).
# check_links_in: tool -> free-text arguments (bodies, subjects) where only links / emails / IBANs are checked.
# outward_args: tool -> arguments where data, money or access leaves the user (used by strict_trust).
# confirmable: tools where a refused call is shown to the user instead of being blocked outright.
# always_confirm: tools that always need the user's OK, even with clean arguments (delete, cancel: an ID
#   can't be traced, so there's nothing to check).
# user_identities: the user's own addresses etc., trusted in every session.

unknown_tools: block      # default-deny: tools in no section don't run
strict_trust: typed       # weak trusted tools' emails / URLs / IBANs don't count for outward args
approval_scope: value     # confirm mode: a yes covers that value for the session (call = one exact call)

trusted_tools: []
weak_trusted_tools: []
safe_tools: []
forbid_tainted: {}
check_links_in: {}
outward_args: {}
confirmable: []
always_confirm: []
user_identities: []

# Not classified yet (blocked while unknown_tools is block):
unclassified:
"""


def load_tool_list(path: str | Path) -> list[dict]:
    """[{"name": ..., "description": ..., "inputSchema": ...}] from any of the accepted JSON shapes."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("result", data)
        data = data.get("tools", data) if isinstance(data, dict) else data
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a tool list (tools/list result, or a list of tools or names)")
    tools = [{"name": t} if isinstance(t, str) else dict(t) for t in data]
    for t in tools:
        if not isinstance(t.get("name"), str) or not t["name"]:
            raise ValueError(f"{path}: every tool needs a name: {t}")
    return tools


def _one_line(text: str, limit: int = 90) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def skeleton(tools: list[dict]) -> str:
    """The policy YAML text. Tool names are JSON-quoted (valid YAML whatever the name)."""
    lines = [HEADER]
    for t in tools:
        props = ((t.get("inputSchema") or {}).get("properties") or {})
        hint = []
        if t.get("description"):
            hint.append(_one_line(t["description"]))
        if props:
            hint.append("args: " + ", ".join(props))
        lines.append(f"  - {json.dumps(t['name'])}" + (f"   # {' | '.join(hint)}" if hint else "") + "\n")
    if not tools:
        lines.append("  []\n")
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tracklimits")
    sub = ap.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="write a policy skeleton from a JSON tool list")
    init.add_argument("tools", help="JSON file: MCP tools/list output, or a list of tools / names")
    init.add_argument("-o", "--output", default="policy.yaml")
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    a = ap.parse_args(argv)
    out = Path(a.output)
    if out.exists() and not a.force:
        ap.error(f"{out} exists (use --force to overwrite)")
    tools = load_tool_list(a.tools)
    out.write_text(skeleton(tools), encoding="utf-8")
    print(f"wrote {out}: {len(tools)} tools, all unclassified (blocked until you classify them)")
    return 0
