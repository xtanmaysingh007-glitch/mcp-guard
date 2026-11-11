"""The `tracklimits` command (installed by pyproject.toml):

    tracklimits init tools.json -o policy.yaml      write a policy skeleton from an MCP tool list (init_policy.py)
    tracklimits proxy --policy P --user-request-file F [options] -- <server command>   run the guard proxy

The proxy needs the MCP SDK (`pip install "tracklimits[proxy]"`); init and the guard itself don't.
"""
from __future__ import annotations

import sys

USAGE = """usage: tracklimits {init,proxy} ...

  init    write a policy skeleton from an MCP tools/list JSON (every tool unclassified, unknown tools blocked)
  proxy   put the guard between an MCP host and a real MCP server (needs the [proxy] extra)

run `tracklimits init --help` or `tracklimits proxy --help` for the options."""


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE)
        return 0 if argv else 2
    command, rest = argv[0], argv[1:]
    if command == "init":
        from .init_policy import main as init_main
        return init_main(["init", *rest])
    if command == "proxy":
        try:
            from .proxy.__main__ import main as proxy_main
        except ImportError as e:        # the MCP SDK isn't installed
            print(f"tracklimits proxy needs the MCP SDK ({e}). Install it with: pip install \"tracklimits[proxy]\"",
                  file=sys.stderr)
            return 1
        proxy_main(rest)
        return 0
    print(f"unknown command {command!r}\n\n{USAGE}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
