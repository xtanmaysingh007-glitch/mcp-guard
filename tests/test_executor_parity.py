"""With nothing to block, GuardedToolsExecutor must give the model exactly what AgentDojo's ToolsExecutor gives it.

Why this exists (2026-11-10): workspace user_task_4 failed on the clean run under tracklimits and confirm_oracle,
but not under none, in F7 and F7r, with no block involved. If the guarded executor formatted a tool result,
an error or the arguments even slightly differently, the model's input would differ and so could its answer.
These tests replay a real logged run (tests/fixtures/ws_user_task_4_none.json, the F7r none run) through both
executors, call by call, on fresh copies of the same environment, and compare the tool messages byte for byte
(and with the logged ones). The guard here has an allow-everything policy: Policy() guards no argument and
lets unknown tools run. (The user_task_4 difference turned out to come from Ollama, not the executor: see
CLAUDE.md, "Clean-run differences between defenses".)
"""
import json
from pathlib import Path

import pytest
from agentdojo.agent_pipeline.tool_execution import EMPTY_FUNCTION_NAME, ToolsExecutor
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from tracklimits.agentdojo_adapter import GuardedToolsExecutor
from tracklimits.guard import Guard
from tracklimits.policy import Policy

FIXTURE = Path(__file__).parent / "fixtures" / "ws_user_task_4_none.json"


def dump(messages) -> str:
    """Messages as the exact JSON text a log (and a byte comparison) would see."""
    return json.dumps(messages, default=lambda o: o.model_dump(), ensure_ascii=False)


def as_call(d: dict) -> FunctionCall:
    return FunctionCall(**d)


def replay(log: dict):
    """Feed every logged assistant turn to both executors; return (plain results, guarded results) per turn."""
    suite = get_suite("v1.2.2", log["suite"])
    task = suite.get_user_task_by_id(log["user_task"])
    env_plain = task.init_environment(suite.load_and_inject_default_environment({}))
    env_guard = task.init_environment(suite.load_and_inject_default_environment({}))
    runtime = FunctionsRuntime(suite.tools)
    guard = Guard(Policy())                                  # allow everything
    guard.start_session(log["messages"][1]["content"][0]["content"])
    plain_exec, guard_exec = ToolsExecutor(), GuardedToolsExecutor(guard)

    turns = []
    for m in log["messages"]:
        if m["role"] != "assistant" or not m.get("tool_calls"):
            continue
        # separate FunctionCall objects per executor: both convert string lists in place (literal_eval)
        a = {**m, "tool_calls": [as_call(t) for t in m["tool_calls"]]}
        b = {**m, "tool_calls": [as_call(t) for t in m["tool_calls"]]}
        _, _, env_plain, out_a, _ = plain_exec.query("q", runtime, env_plain, [a], {})
        _, _, env_guard, out_b, _ = guard_exec.query("q", runtime, env_guard, [b], {})
        turns.append((out_a[1:], out_b[1:]))
    return turns


def test_guarded_executor_matches_agentdojo_byte_for_byte_on_a_real_run():
    log = json.loads(FIXTURE.read_text(encoding="utf-8"))
    turns = replay(log)
    assert turns, "the fixture has tool calls"
    for plain, guarded in turns:
        assert dump(guarded) == dump(plain)


def sort_participants(text: str) -> str:
    """AgentDojo's create_event does participants = list(set(participants)), so their order depends on the
    process's string-hash seed (PYTHONHASHSEED): it differs between any two runs, under every defense."""
    out, block = [], []
    for line in text.split("\n") + [""]:
        if line.startswith("- ") and out and (out[-1] == "participants:" or block):
            block.append(line)              # a list item right under "participants:"
            continue
        if block:
            out += sorted(block)
            block = []
        out.append(line)
    return "\n".join(out[:-1])


def test_replayed_tool_messages_match_the_logged_ones():
    """And both match what the live none run logged (so the replay itself is faithful), up to the
    participant order that AgentDojo randomizes itself."""
    log = json.loads(FIXTURE.read_text(encoding="utf-8"))
    logged = [m for m in log["messages"] if m["role"] == "tool"]
    replayed = json.loads(dump([msg for _, guarded in replay(log) for msg in guarded]))
    for msgs in (logged, replayed):
        for m in msgs:
            m["content"][0]["content"] = sort_participants(m["content"][0]["content"])
    assert replayed == logged


@pytest.mark.parametrize("calls", [
    [FunctionCall(function=EMPTY_FUNCTION_NAME, args={}, id="c1")],                  # model gave no function name
    [FunctionCall(function="", args={}, id="c1")],
    [FunctionCall(function="no_such_tool", args={}, id="c1")],                       # unknown tool
    [FunctionCall(function="get_day_calendar_events", args={"day": "2024-05-15"}, id="c1"),
     FunctionCall(function="get_day_calendar_events", args={"day": "2024-05-15"}, id="c2")],   # duplicate call
    [FunctionCall(function="create_calendar_event", id="c1",
                  args={"title": "x", "start_time": "2024-05-19 12:00", "end_time": "2024-05-19 13:00",
                        "participants": "['a@b.com', 'c@d.com']"})],                 # string list -> literal_eval
    [FunctionCall(function="get_day_calendar_events", args={"day": "not a date"}, id="c1")],   # tool error
])
def test_edge_cases_match_agentdojo(calls):
    suite = get_suite("v1.2.2", "workspace")
    runtime = FunctionsRuntime(suite.tools)
    outs = []
    for executor in (ToolsExecutor(), GuardedToolsExecutor(Guard(Policy()))):
        env = suite.load_and_inject_default_environment({})
        msg = {"role": "assistant", "content": None,
               "tool_calls": [FunctionCall(**c.model_dump()) for c in calls]}
        _, _, _, out, _ = executor.query("q", runtime, env, [msg], {})
        outs.append(dump(out[1:]))
    assert outs[1] == outs[0]
