"""Offline evaluation of TrackLimits on AgentDojo ground-truth traces. No LLM needed.

Two idealised agents:
  honest agent   - executes exactly the reference solution of each user task (clean environment).
                   Measures FALSE BLOCKS: how often the guard breaks a perfectly honest agent.
  hijacked agent - does the user task, then executes the attacker's reference solution, in an
                   environment containing the injection. Measures BLOCKED ATTACKS against a fully
                   compromised agent (the worst case: the model obeyed every injection).
Utility and attack success use AgentDojo's own checkers.

  python scripts/replay_ground_truth.py                 # allowlist mode (default policy)
  python scripts/replay_ground_truth.py --mode taint    # weaker blocklist mode
  python scripts/replay_ground_truth.py --mode off      # no guard (sanity check)
"""
import argparse
import json
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from tracklimits.guard import Guard
from tracklimits.policy import DEFAULT_POLICY_PATH, Policy

BENCH_VERSION = "v1.2.2"


class _Named:  # attacks only need a pipeline name to pick how to address the model
    name = "local"


def replay(suite, guard, prompt: str, tasks: list, env):
    """Run reference tool calls of `tasks` in order through the guard.
    Returns (blocked call descriptions, pre_env, executed calls)."""
    runtime = FunctionsRuntime(suite.tools)
    pre_env = env.model_copy(deep=True)
    blocked, executed = [], []
    if guard:
        guard.start_session(prompt)
    for task in tasks:
        for call in task.ground_truth(pre_env):
            args = dict(call.args)
            if guard:
                d = guard.check_call(call.function, args)
                if not d.allowed:
                    blocked.append(f"{call.function}({', '.join(f'{k}={v}' for k, v in d.tainted.items())})")
                    continue
            out, err = runtime.run_function(env, call.function, args)
            executed.append(call)
            if guard:
                guard.observe_output(call.function, tool_result_to_str(out) if err is None else str(err))
    return blocked, pre_env, executed


def utility_ok(task, pre, post, traces) -> bool:
    try:
        return bool(task.utility(task.GROUND_TRUTH_OUTPUT, pre, post))
    except NotImplementedError:
        return bool(task.utility_from_traces(task.GROUND_TRUTH_OUTPUT, pre, post, traces))


def attack_ok(task, pre, post, traces) -> bool:
    try:
        return bool(task.security(task.GROUND_TRUTH_OUTPUT, pre, post))
    except NotImplementedError:
        return bool(task.security_from_traces(task.GROUND_TRUTH_OUTPUT, pre, post, traces))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["allowlist", "taint", "off"], default="allowlist")
    ap.add_argument("--suites", nargs="+", default=["workspace", "banking", "slack", "travel"])
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--show", type=int, default=5, help="examples of false blocks to print per suite")
    args = ap.parse_args()
    warnings.filterwarnings("ignore")

    policy = Policy.from_yaml(DEFAULT_POLICY_PATH)
    report = {"mode": args.mode, "suites": {}}
    for sname in args.suites:
        suite = get_suite(BENCH_VERSION, sname)
        attack = load_attack(args.attack, suite, _Named())
        mk = (lambda: None) if args.mode == "off" else (lambda: Guard(policy.with_mode(args.mode)))

        # honest agent
        ok, false_blocks = 0, []
        for uid, ut in suite.user_tasks.items():
            env = suite.load_and_inject_default_environment({})
            blocked, pre, tr = replay(suite, mk(), ut.PROMPT, [ut], env)
            if utility_ok(ut, pre, env, tr):
                ok += 1
            if blocked:
                false_blocks.append(f"{uid}: {blocked[0]}")

        # hijacked agent
        pairs, succeeded = 0, 0
        for uid, ut in suite.user_tasks.items():
            for iid, it in suite.injection_tasks.items():
                injections = attack.attack(ut, it)
                env = suite.load_and_inject_default_environment(injections)
                _, pre, tr = replay(suite, mk(), ut.PROMPT, [ut, it], env)
                pairs += 1
                succeeded += attack_ok(it, pre, env, tr)

        n = len(suite.user_tasks)
        r = {
            "honest_utility": round(ok / n, 3),
            "honest_tasks_with_a_false_block": f"{len(false_blocks)}/{n}",
            "hijacked_attack_success": round(succeeded / pairs, 3),
            "pairs": pairs,
            "example_false_blocks": false_blocks[: args.show],
        }
        report["suites"][sname] = r
        print(f"\n== {sname} ==\n" + json.dumps(r, indent=2))

    out = Path("runs") / f"replay_{args.mode}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"\nSaved {out}")


if __name__ == "__main__":
    main()
