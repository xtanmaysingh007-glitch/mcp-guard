"""--freeze-clock: AgentDojo's wall-clock stamps on NEWLY created objects get a fixed value (benchmark only).

AgentDojo 0.1.35 stamps with datetime.now() in exactly these places (workspace only; slack, banking and travel
have none): send_email -> the new email's timestamp; create_file -> last_modified; append_to_file ->
last_modified of the file it changes; and the Email model's timestamp default. The model reads these stamps
(F8, 2026-11-10: the one log that still differed between two identical runs split right after an email
timestamp). Frozen, they come from a clock that starts at FROZEN_START (later than every date in the suites'
data, like the real clock) and ticks 1 second per stamp; it restarts at the beginning of every task. The
environment's current day and all pre-existing data are untouched, and with the flag off nothing changes.
"""
import datetime
import warnings

import pytest
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from mcp_guard import agentdojo_clock as clock
from mcp_guard.agentdojo_clock import FROZEN_START, freeze_clock, reset_clock, unfreeze_clock


@pytest.fixture(autouse=True)
def real_clock_after_each_test():
    yield
    unfreeze_clock()


def workspace():
    suite = get_suite("v1.2.2", "workspace")
    return suite, suite.load_and_inject_default_environment({}), FunctionsRuntime(suite.tools)


def send(env, runtime):
    out, err = runtime.run_function(env, "send_email", {"recipients": ["bob@x.com"], "subject": "s", "body": "b"})
    assert err is None
    return out.timestamp


def test_off_by_default_stamps_are_the_real_time():
    suite, env, rt = workspace()
    before = datetime.datetime.now()
    assert before <= send(env, rt) <= datetime.datetime.now()


def test_frozen_new_objects_get_the_fixed_clock():
    freeze_clock()
    reset_clock()
    suite, env, rt = workspace()
    assert send(env, rt) == FROZEN_START
    assert send(env, rt) == FROZEN_START + datetime.timedelta(seconds=1)
    f, err = rt.run_function(env, "create_file", {"filename": "a.txt", "content": "x"})
    assert err is None and f.last_modified == FROZEN_START + datetime.timedelta(seconds=2)


def test_frozen_append_is_later_than_the_old_stamp_and_existing_data_is_untouched():
    pristine = workspace()[1]
    freeze_clock()
    reset_clock()
    suite, env, rt = workspace()
    # nothing pre-existing changed: emails, files, calendar, current day
    assert env.model_dump() == pristine.model_dump()
    assert env.calendar.current_day == pristine.calendar.current_day
    old = env.cloud_drive.files["3"].last_modified
    out, err = rt.run_function(env, "append_to_file", {"file_id": "3", "content": "more"})
    assert err is None and out.last_modified == FROZEN_START and out.last_modified > old


def test_the_clock_restarts_for_every_task():
    freeze_clock()
    suite, env1, rt = workspace()
    reset_clock()
    first = send(env1, rt)
    env2 = suite.load_and_inject_default_environment({})
    reset_clock()
    assert send(env2, rt) == first


def test_frozen_start_is_later_than_every_date_in_the_suites():
    assert clock.latest_data_timestamp() < FROZEN_START


def test_unfreeze_restores_the_real_clock():
    freeze_clock()
    unfreeze_clock()
    suite, env, rt = workspace()
    assert abs((send(env, rt) - datetime.datetime.now()).total_seconds()) < 60


def ground_truth_scores(suite_name):
    """Every user task's utility and every injection task's security, from their reference solutions."""
    suite = get_suite("v1.2.2", suite_name)
    rt = FunctionsRuntime(suite.tools)

    class Named:
        name = "local"

    attack = load_attack("important_instructions", suite, Named())
    scores = {}
    for uid, task in suite.user_tasks.items():
        reset_clock()
        env = suite.load_and_inject_default_environment({})
        env = task.init_environment(env)
        pre = env.model_copy(deep=True)
        traces = []
        for call in task.ground_truth(pre):
            rt.run_function(env, call.function, dict(call.args))
            traces.append(call)
        try:
            scores[uid] = bool(task.utility(task.GROUND_TRUTH_OUTPUT, pre, env))
        except NotImplementedError:
            scores[uid] = bool(task.utility_from_traces(task.GROUND_TRUTH_OUTPUT, pre, env, traces))
    user = next(iter(suite.user_tasks.values()))
    for iid, inj in suite.injection_tasks.items():
        reset_clock()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            injections = attack.attack(user, inj)
        env = suite.load_and_inject_default_environment(injections)
        pre = env.model_copy(deep=True)
        traces = []
        for call in inj.ground_truth(pre):
            rt.run_function(env, call.function, dict(call.args))
            traces.append(call)
        try:
            scores[iid] = bool(inj.security(inj.GROUND_TRUTH_OUTPUT, pre, env))
        except NotImplementedError:
            scores[iid] = bool(inj.security_from_traces(inj.GROUND_TRUTH_OUTPUT, pre, env, traces))
    return scores


@pytest.mark.parametrize("suite_name", ["workspace", "slack", "banking", "travel"])
def test_no_ground_truth_score_changes_with_a_frozen_clock(suite_name):
    real = ground_truth_scores(suite_name)
    freeze_clock()
    frozen = ground_truth_scores(suite_name)
    assert frozen == real


def test_every_pipeline_restarts_the_clock_per_task():
    """The same task run twice through a pipeline gets the same stamps (ResetClock is the first element)."""
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.functions_runtime import EmptyEnv
    from agentdojo.types import text_content_block_from_string
    from mcp_guard.agentdojo_adapter import build_pipeline

    class SendsOnce(BasePipelineElement):
        name = "local-test"

        def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
            if any(m["role"] == "tool" for m in messages):
                msg = {"role": "assistant", "content": [text_content_block_from_string("ok")], "tool_calls": None}
            else:
                msg = {"role": "assistant", "content": None, "tool_calls": [FunctionCall(
                    function="send_email", id="c1",
                    args={"recipients": ["emma.johnson@bluesparrowtech.com"], "subject": "s", "body": "b"})]}
            return query, runtime, env, [*messages, msg], extra_args

    freeze_clock()
    for defense in ["none", "mcp_guard", "mcp_guard_confirm_oracle"]:
        stamps = []
        for _ in range(2):
            suite, env, rt = workspace()
            pipeline, _ = build_pipeline(SendsOnce(), "local-test", defense)
            send(env, rt)                          # a stamp from "an earlier task": must not carry over
            pipeline.query("Email me", rt, env)
            stamps.append(env.inbox.emails[max(env.inbox.emails, key=int)].timestamp)
        assert stamps == [FROZEN_START, FROZEN_START], defense


def test_run_batch_passes_the_flag_to_every_run(monkeypatch):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import run_batch
    cmds = []
    monkeypatch.setattr(run_batch.subprocess, "call", lambda cmd, **kw: cmds.append(cmd) or 0)
    monkeypatch.setattr(run_batch, "unload_models", lambda: None)
    monkeypatch.setattr(sys, "argv", ["run_batch.py", "--suite", "workspace", "--defenses", "none", "mcp_guard",
                                      "--freeze-clock"])
    run_batch.main()
    assert len(cmds) == 2 and all("--freeze-clock" in c for c in cmds)


def test_run_agentdojo_labels_frozen_runs():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import run_agentdojo
    assert run_agentdojo.log_dir("none", rep=1, freeze_clock=False) == Path("runs") / "none"
    assert run_agentdojo.log_dir("none", rep=1, freeze_clock=True) == Path("runs") / "none" / "clock-frozen"
    assert run_agentdojo.log_dir("none", rep=2, freeze_clock=True) == Path("runs") / "none" / "clock-frozen" / "rep2"


def test_attribution_finds_and_labels_frozen_runs(tmp_path, monkeypatch, capsys):
    import json as _json
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import attribution
    for sub in ["none", "none/clock-frozen", "none/clock-frozen/rep2"]:
        d = tmp_path / "runs" / sub / "local-m-none" / "workspace" / "user_task_0" / "important_instructions"
        d.mkdir(parents=True)
        (d / "injection_task_0.json").write_text(_json.dumps({"messages": [{"role": "user", "content": "x"}]}))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["attribution.py", "--suite", "workspace", "--model", "local-m"])
    attribution.main()
    out = capsys.readouterr().out
    assert "none rep1 " in out and "none rep1 [clock-frozen]" in out and "none rep2 [clock-frozen]" in out
