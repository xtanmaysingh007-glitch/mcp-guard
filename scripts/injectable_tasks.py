"""List the user tasks an attack can actually reach, per suite.

AgentDojo only places an injection where the task's CORRECT solution would read it
(BaseAttack.get_injection_candidates replays the ground-truth calls with canary text in every
injection slot and keeps the slots whose canary shows up in a tool output). A task with no
candidates can't be attacked at all (AgentDojo raises "... is not injectable").

We also mark which tasks' ground truth calls a tool the guard checks (forbid_tainted or
check_links_in in the policy). A task that only reads can still be attacked, but the attacker then
has to get the model to call a new tool; a task that already writes is where the guard is in the path.

usage: python scripts/injectable_tasks.py [--suites workspace slack] [--attack important_instructions]
Prints, per suite, a ready-to-paste --user-tasks list of "injectable AND calls a guarded tool".
"""
import argparse
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from tracklimits.policy import DEFAULT_POLICY_PATH, Policy  # noqa: E402

from agentdojo.attacks.attack_registry import load_attack
from agentdojo.task_suite.load_suites import get_suite

BENCH_VERSION = "v1.2.2"


class _NamedPipeline:
    """The attack only needs a pipeline name (to say "AI model developed by ..."); nothing is run."""
    name = "local-listing"


def task_number(task_id: str) -> int:
    return int(task_id.split("_")[-1])


def injectable_tasks(suite_name: str, attack_name: str, guarded: set[str]):
    """Yield (task_id, candidates, guarded_tools_in_ground_truth) for every user task."""
    suite = get_suite(BENCH_VERSION, suite_name)
    attack = load_attack(attack_name, suite, _NamedPipeline())
    env = suite.load_and_inject_default_environment(suite.get_injection_vector_defaults())
    for tid in sorted(suite.user_tasks, key=task_number):
        task = suite.user_tasks[tid]
        try:
            cands = attack.get_injection_candidates(task)
        except ValueError:  # "not injectable"
            cands = []
        calls = {c.function for c in task.ground_truth(env.model_copy(deep=True))}
        yield tid, cands, sorted(calls & guarded)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suites", nargs="+", default=["workspace", "slack", "banking", "travel"])
    ap.add_argument("--attack", default="important_instructions")
    a = ap.parse_args()
    policy = Policy.from_yaml(DEFAULT_POLICY_PATH)
    guarded = set(policy.forbid_tainted) | set(policy.check_links_in)
    warnings.filterwarnings("ignore")

    for suite_name in a.suites:
        rows = list(injectable_tasks(suite_name, a.attack, guarded))
        print(f"\n== {suite_name}: {len(rows)} user tasks")
        for tid, cands, gtools in rows:
            print(f"  {tid:13} {'INJ' if cands else '---'}  guarded={','.join(gtools) or '-':40} "
                  f"slots={','.join(cands) or '-'}")
        inj = [task_number(t) for t, c, _ in rows if c]
        both = [task_number(t) for t, c, g in rows if c and g]
        empty = [task_number(t) for t, c, _ in rows if not c]
        print(f"  injectable: {len(inj)}   not injectable: {empty or 'none'}")
        print(f"  injectable + guarded tool ({len(both)}): --user-tasks {' '.join(map(str, both))}")


if __name__ == "__main__":
    main()
