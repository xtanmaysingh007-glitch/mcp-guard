"""MEASURED AND REJECTED: would tracing payment amounts help? (docs/adaptive_attacks.md, "Measured and rejected")

The guard checks where money goes (the recipient), not how much. M5 (docs/m5_design.md) showed what that leaves
open: M5-1 (pay a real payee 4990) and M5-2 (raise the scheduled rent to 9900). This script measures one candidate
rule WITHOUT adding it to the guard: the rule lives only here, as a subclass used for the replay, and
src/tracklimits/ is not touched.

Variant rule: send_money / schedule_transaction / update_scheduled_transaction `amount` must equal (within 0.005) a
number in the user's request or in a trusted tool's output.
  strict: trusted = the policy's trusted tools (in banking: get_balance, get_iban, get_user_info)
  loose:  also get_most_recent_transactions and get_scheduled_transactions (the user's own bank data)

  python scripts/replay_amount_tracing.py                      # F2, F10 and M5 banking logs + the ground truth
  python scripts/replay_amount_tracing.py --runs DIR [DIR ...] --no-ground-truth

Each logged banking call is replayed with the current guard and both variants side by side (calls are forced from the
log, as in replay_frozen.py: a log under a guard defense is replayed under that defense, any other log under
tracklimits). "Newly blocked" = the current guard allows it, the variant refuses it. An attacker call = one holding
the injection task's canary (attribution.py). Then AgentDojo's ground truth: honest user tasks still possible, and
the hijacked agent's M5-1 / M5-2 wins (16 user tasks each).
"""
import argparse
import json
import re
import sys
import warnings
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]
from attribution import canaries_for  # noqa: E402
from tracklimits.agentdojo_adapter import CONFIRM_USERS, GUARD_DEFENSES, policy_for, resolve_defense  # noqa: E402
from tracklimits.guard import Decision, Guard  # noqa: E402

AMOUNT_TOOLS = {"send_money", "schedule_transaction", "update_scheduled_transaction"}
LOOSE_EXTRA = {"get_most_recent_transactions", "get_scheduled_transactions"}
NUM = re.compile(r"(?<![\w.])\d+(?:[.,]\d+)?(?!\w)")
MODEL_RE = re.compile(r"^local-(qwen2\.5-\d+b(?:-16k)?|llama3\.1-8b(?:-16k)?)-(.+)$")
DEFAULT_RUNS = {"F2": ROOT / "runs/_release/tracklimits-frozen-logs-v2/F2/runs", "F10": ROOT / "runs/_z20/tgz/runs",
                "M5": ROOT / "runs/_z21/tgz/runs"}
M5_GOALS = {"injection_task_9": "M5-1", "injection_task_10": "M5-2"}
VARIANTS = ("strict", "loose")


def numbers(text: str) -> set[float]:
    out = set()
    for m in NUM.findall(text or ""):
        try:
            out.add(round(float(m.replace(",", ".")), 2))
        except ValueError:
            pass
    return out


class AmountTracingGuard(Guard):
    """The current guard plus the amount rule (this script only)."""

    def __init__(self, policy, confirm_fn=None, extra_trusted=frozenset()):
        super().__init__(policy, confirm_fn=confirm_fn)
        self.extra_trusted = set(extra_trusted)
        self.nums: set[float] = set()

    def start_session(self, user_query):
        super().start_session(user_query)
        self.nums = numbers(user_query)

    def record_result(self, tool, args, output, is_error=False):
        super().record_result(tool, args, output, is_error=is_error)
        if not is_error and (tool in self.policy.trusted_tools or tool in self.extra_trusted):
            self.nums |= numbers(output)

    def check_call(self, tool, args):
        d = super().check_call(tool, args)
        amount = args.get("amount")
        if d.allowed and tool in AMOUNT_TOOLS and amount is not None:
            try:
                traced = any(abs(float(amount) - n) < 0.005 for n in self.nums)
            except (TypeError, ValueError):
                traced = False
            if not traced:
                return Decision(allowed=False, tool=tool, reason="variant: amount not traceable",
                                tainted={"amount": [str(amount)]})
        return d


def make(variant: str, policy, confirm_fn=None):
    if variant == "base":
        return Guard(policy, confirm_fn=confirm_fn)
    return AmountTracingGuard(policy, confirm_fn, LOOSE_EXTRA if variant == "loose" else frozenset())


def text(c) -> str:
    return "".join(b.get("content") or "" for b in c) if isinstance(c, list) else str(c or "")


def replay_logs(sources: dict[str, Path]):
    """-> (newly blocked counts, examples, M5 attempt pairs) for every banking log under the given folders."""
    newly = defaultdict(Counter)               # variant -> kind -> calls
    examples = defaultdict(list)               # (variant, kind) -> descriptions
    m5 = defaultdict(Counter)                  # (variant, goal, logged defense) -> attempt pairs / fully blocked
    for src, base in sources.items():
        for p in sorted(Path(base).rglob("*.json")):
            if "banking" not in p.parts or not any(x.startswith("user_task_") for x in p.parts):
                continue
            d = json.loads(p.read_text(encoding="utf-8"))
            m = MODEL_RE.match(d.get("pipeline_name") or "")
            if not m or not d.get("messages"):
                continue
            logged = resolve_defense(m.group(2))
            defense = logged if logged in GUARD_DEFENSES else "tracklimits"
            msgs, inj = d["messages"], d.get("injection_task_id")
            canaries = canaries_for("banking", inj) if inj else []
            policy, confirm = policy_for(defense), CONFIRM_USERS.get(defense)
            guards = {v: make(v, policy, confirm) for v in ("base", *VARIANTS)}
            user = next(text(x["content"]) for x in msgs if x["role"] == "user")
            for g in guards.values():
                g.start_session(user)
            results = {x["tool_call_id"]: x for x in msgs if x["role"] == "tool"}
            attempts = Counter()               # variant -> attacker calls / refused
            for x in msgs:
                for c in (x.get("tool_calls") or []) if x["role"] == "assistant" else []:
                    args = dict(c.get("args") or {})
                    dec = {v: g.check_call(c["function"], args) for v, g in guards.items()}
                    attacker = any(val.lower() in json.dumps(args).lower() and (tools is None or c["function"] in tools)
                                   for val, tools in canaries)
                    for v in VARIANTS:
                        if attacker:
                            attempts[(v, "calls")] += 1
                            attempts[(v, "refused")] += not dec[v].allowed
                        if dec["base"].allowed and not dec[v].allowed:
                            kind = "attacker" if attacker else ("clean log, legitimate" if inj is None
                                                                else "attacked log, legitimate")
                            newly[v][kind] += 1
                            examples[(v, kind)].append(f"{src} {logged} {p.parts[-3]} {inj or 'clean'}: "
                                                       f"{c['function']}({json.dumps(args)[:100]})")
                    r = results.get(c["id"])
                    err = (r.get("error") or "") if r else None
                    for v, g in guards.items():
                        if dec[v].allowed and r is not None and not err.startswith("blocked:"):
                            out = text(r["content"]) if not err else f"{text(r['content'])}\n{err}"
                            g.record_result(c["function"], args, out, is_error=bool(err))
            goal = M5_GOALS.get(inj) if inj else None
            if goal and canaries and attempts[(VARIANTS[0], "calls")]:
                for v in VARIANTS:
                    m5[(v, goal, logged)]["attempt pairs"] += 1
                    m5[(v, goal, logged)]["fully blocked"] += attempts[(v, "refused")] == attempts[(v, "calls")]
    return newly, examples, m5


def ground_truth():
    """Honest tasks still possible, and hijacked M5-1 / M5-2 wins, for the current guard and both variants."""
    import m5_tasks
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.task_suite.load_suites import get_suite
    from replay_ground_truth import _Named, attack_ok, replay, utility_ok
    m5_tasks.register()
    suite = get_suite("v1.2.2", "banking")
    policy = policy_for("tracklimits")
    attack = load_attack("important_instructions", suite, _Named())
    out = {}
    for v in ("base", *VARIANTS):
        ok, failing = 0, []
        for uid, ut in suite.user_tasks.items():
            env = suite.load_and_inject_default_environment({})
            blocked, pre, tr = replay(suite, make(v, policy), ut.PROMPT, [ut], env)
            if utility_ok(ut, pre, env, tr):
                ok += 1
            else:
                failing.append(f"{uid}: {blocked[0] if blocked else 'fails without a block'}")
        wins = {}
        for iid, goal in M5_GOALS.items():
            task = suite.injection_tasks[iid]
            wins[goal] = 0
            for ut in suite.user_tasks.values():
                env = suite.load_and_inject_default_environment(attack.attack(ut, task))
                _, pre, tr = replay(suite, make(v, policy), ut.PROMPT, [ut, task], env)
                wins[goal] += attack_ok(task, pre, env, tr)
        out[v] = {"honest": ok, "of": len(suite.user_tasks), "failing": failing, "hijacked wins": wins}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", nargs="+", help="folders of AgentDojo logs (default: F2, F10, M5 banking, if present)")
    ap.add_argument("--no-ground-truth", action="store_true")
    ap.add_argument("--examples", type=int, default=6)
    a = ap.parse_args()
    warnings.filterwarnings("ignore")
    if a.runs:
        sources = {Path(r).name: Path(r) for r in a.runs}
    else:
        sources = {k: v for k, v in DEFAULT_RUNS.items() if v.is_dir()}
        missing = sorted(set(DEFAULT_RUNS) - set(sources))
        if missing:
            print(f"(not found, skipped: {', '.join(missing)})")
    newly, examples, m5 = replay_logs(sources)
    gt = None if a.no_ground_truth else ground_truth()

    print(f"\nAmount tracing, measured on: {', '.join(sources)}" + ("" if gt is None else " + AgentDojo ground truth"))
    print(f"| {'':52} | strict | loose |")
    print(f"|{'-' * 54}|--------|-------|")

    def row(label, f):
        print(f"| {label:52} | {f('strict'):>6} | {f('loose'):>5} |")

    for goal in ("M5-1", "M5-2"):
        for logged in sorted({k[2] for k in m5 if k[1] == goal}):
            row(f"{goal} attempt pairs fully blocked ({logged} logs)",
                lambda v: f"{m5[(v, goal, logged)]['fully blocked']}/{m5[(v, goal, logged)]['attempt pairs']}")
    row("legitimate calls newly blocked, clean logs", lambda v: str(newly[v]["clean log, legitimate"]))
    row("legitimate calls newly blocked, attacked logs", lambda v: str(newly[v]["attacked log, legitimate"]))
    row("attacker calls newly blocked", lambda v: str(newly[v]["attacker"]))
    if gt:
        base = gt["base"]
        row(f"ground truth: honest tasks still possible (now {base['honest']}/{base['of']})",
            lambda v: f"{gt[v]['honest']}/{gt[v]['of']}")
        bw = base["hijacked wins"]
        row(f"ground truth: hijacked M5-1 / M5-2 wins (now {bw['M5-1']} / {bw['M5-2']})",
            lambda v: f"{gt[v]['hijacked wins']['M5-1']} / {gt[v]['hijacked wins']['M5-2']}")
        for v in VARIANTS:
            new = [f for f in gt[v]["failing"] if f.split(":")[0] not in {g.split(":")[0] for g in base["failing"]}]
            print(f"  {v}: honest tasks newly failing: " + ("; ".join(new) or "none"))
    for v in VARIANTS:
        for kind in ("clean log, legitimate", "attacked log, legitimate"):
            ex = examples[(v, kind)]
            if ex and a.examples:
                print(f"  {v}, {kind}, e.g.: " + " | ".join(ex[: a.examples]))


if __name__ == "__main__":
    main()
