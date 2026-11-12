"""Runs must repeat: the same task under the same model should give the same transcript, under every defense.

2026-11-10 investigation (docs/PROJECT_NOTES.md, "Clean-run differences between defenses"): Qwen on Ollama at temperature 0
was not repeatable, for reasons outside the guard that hit every defense alike:
  1. Ollama returns a tool call's arguments in a random key order (Go map iteration), and AgentDojo sends them
     back in the next prompt, so the model's input changed at random.            -> SortToolArgs
  2. AgentDojo builds some tool outputs from Python sets (event participants), whose order depends on the
     process's string-hash seed.                                                  -> PYTHONHASHSEED=0
  3. Ollama's prompt cache: the first run of a defense reused tokens cached by the previous defense.
                                                                                  -> unload models between defenses
"""
import json
import sys
from pathlib import Path

import pytest
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, FunctionCall, FunctionsRuntime, make_function
from agentdojo.types import text_content_block_from_string

from tracklimits.agentdojo_adapter import SortToolArgs, build_pipeline

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_batch  # noqa: E402

SCRAMBLED = {"title": "Lunch", "participants": ["a@b.com"], "end_time": "13:00",
             "extra": {"z": 1, "a": 2}, "description": "x", "start_time": "12:00"}


def create_event(title: str, start_time: str, end_time: str, description: str, participants: list[str],
                 extra: dict) -> str:
    """Stub calendar tool.

    :param title: title
    :param start_time: start
    :param end_time: end
    :param description: description
    :param participants: participants
    :param extra: anything
    """
    return "created"


class ScrambledLLM(BasePipelineElement):
    """First reply: one tool call with keys in a random-looking order (like Ollama). Records what it is sent."""
    name = "local-test"

    def __init__(self):
        self.seen = []

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        self.seen.append([m for m in messages])
        if not any(m["role"] == "tool" for m in messages):
            call = FunctionCall(function="create_event", args=dict(SCRAMBLED), id="c1")
            msg = {"role": "assistant", "content": None, "tool_calls": [call]}
        else:
            msg = {"role": "assistant", "content": [text_content_block_from_string("done")], "tool_calls": None}
        return query, runtime, env, [*messages, msg], extra_args


def sent_args(messages):
    """The arguments as AgentDojo's OpenAILLM serializes them into the next prompt: json.dumps(args)."""
    return [json.dumps(t.args) for m in messages if m["role"] == "assistant" for t in (m.get("tool_calls") or [])]


def test_sort_tool_args_sorts_keys_recursively():
    llm = ScrambledLLM()
    _, _, _, msgs, _ = SortToolArgs(llm).query("q", FunctionsRuntime([]), messages=[])
    args = msgs[-1]["tool_calls"][0].args
    assert list(args) == sorted(SCRAMBLED)
    assert list(args["extra"]) == ["a", "z"]
    assert args == SCRAMBLED                       # same content, only the order changed


@pytest.mark.parametrize("defense", ["none", "tracklimits", "tracklimits_confirm_oracle", "spotlighting",
                                     "repeat_user_prompt"])
def test_every_defense_sends_the_model_sorted_args(defense):
    llm = ScrambledLLM()
    pipeline, guard = build_pipeline(llm, "local-test", defense)
    if guard:                                      # nothing to block here: the stub tool is not in the policy
        guard.policy = guard.policy.with_unknown_tools("allow")
    pipeline.query("Make a lunch event", FunctionsRuntime([make_function(create_event)]))
    second_prompt = llm.seen[-1]
    assert sent_args(second_prompt) == [json.dumps(dict(sorted(SCRAMBLED.items())) | {"extra": {"a": 2, "z": 1}})]


def test_children_get_a_fixed_hash_seed(monkeypatch):
    calls = []
    monkeypatch.setattr(run_batch.subprocess, "call", lambda cmd, **kw: calls.append(kw) or 0)
    monkeypatch.setattr(run_batch, "unload_models", lambda: None)
    monkeypatch.setattr(sys, "argv", ["run_batch.py", "--suite", "workspace", "--defenses", "none", "tracklimits"])
    run_batch.main()
    assert len(calls) == 2
    assert all(kw["env"]["PYTHONHASHSEED"] == "0" for kw in calls)


def test_models_are_unloaded_before_every_defense(monkeypatch):
    events = []
    monkeypatch.setattr(run_batch.subprocess, "call", lambda cmd, **kw: events.append(cmd[cmd.index("--defense") + 1]) or 0)
    monkeypatch.setattr(run_batch, "unload_models", lambda: events.append("unload"))
    monkeypatch.setattr(sys, "argv", ["run_batch.py", "--suite", "workspace", "--defenses", "none", "tracklimits",
                                      "tracklimits_confirm_oracle"])
    run_batch.main()
    assert events == ["unload", "none", "unload", "tracklimits", "unload", "tracklimits_confirm_oracle"]


def test_unload_models_asks_ollama_to_drop_every_loaded_model(monkeypatch):
    posted, loaded = [], [["qwen2.5-14b-16k:latest"], []]       # loaded before, then gone

    class Resp:
        def __init__(self, data): self.data = data
        def json(self): return self.data
        def raise_for_status(self): pass

    monkeypatch.setattr(run_batch.httpx, "get", lambda url, **kw: Resp({"models": [{"name": n} for n in loaded.pop(0)]}))
    monkeypatch.setattr(run_batch.httpx, "post", lambda url, json, **kw: posted.append((url, json)) or Resp({}))
    monkeypatch.setattr(run_batch.time, "sleep", lambda s: None)
    run_batch.unload_models()
    assert posted == [("http://localhost:11434/api/generate", {"model": "qwen2.5-14b-16k:latest", "keep_alive": 0})]


def test_unload_models_never_stops_a_run(monkeypatch):
    def down(*a, **kw):
        raise run_batch.httpx.ConnectError("no ollama")
    monkeypatch.setattr(run_batch.httpx, "get", down)
    run_batch.unload_models()                      # prints a note, does not raise
