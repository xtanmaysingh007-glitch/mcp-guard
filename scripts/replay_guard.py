"""Replay a logged AgentDojo run through the CURRENT guard, with no model.

Feeds the logged tool calls to the guard one by one, in the same order, and prints what the guard would
decide now. Useful after a policy change ("would this leak be stopped now?") without spending GPU time.

Caveat: the calls are forced from the log. If the guard now refuses a call the model made, the replay
can't show what the model would have done next; only a live rerun shows that.

usage: python scripts/replay_guard.py <log.json> <defense>
  e.g. python scripts/replay_guard.py runs/tracklimits/.../user_task_20/tool_knowledge/injection_task_1.json tracklimits
  defense: tracklimits, tracklimits_taint, tracklimits_confirm_{no,yes,oracle}, tracklimits_no_trusted, tracklimits_no_links
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from tracklimits.agentdojo_adapter import CONFIRM_USERS, GUARD_DEFENSES, LEGACY_DEFENSE_NAMES, policy_for, resolve_defense  # noqa: E402
from tracklimits.guard import Guard  # noqa: E402


def text(content) -> str:
    """AgentDojo stores message content as a list of {"type": "text", "content": ...} blocks."""
    if isinstance(content, list):
        return "".join(b.get("content") or "" for b in content)
    return str(content or "")


def replay(log_path: str, defense: str) -> dict:
    log = json.loads(Path(log_path).read_text(encoding="utf-8"))
    msgs = log["messages"]
    defense = resolve_defense(defense)          # old mcp_guard... names (frozen logs) work too
    guard = Guard(policy_for(defense), confirm_fn=CONFIRM_USERS.get(defense))
    guard.start_session(text(next(m for m in msgs if m["role"] == "user")["content"]))

    decisions = {}  # tool_call_id -> the guard's new decision
    for m in msgs:
        if m["role"] == "assistant":
            for call in m.get("tool_calls") or []:
                d = guard.check_call(call["function"], dict(call["args"]))
                decisions[call["id"]] = d
                verdict = ("ALLOW" if d.allowed else "BLOCK") + (" (asked)" if d.asked else "")
                print(f"  {call['function']}({json.dumps(call['args'])[:70]}) -> {verdict} {d.reason[:80]}")
        elif m["role"] == "tool":
            # The guard only sees outputs of calls it would allow now, and only ones that actually ran.
            # (A call blocked in the original run has no real output in the log, so nothing to observe.)
            d = decisions.get(m["tool_call_id"])
            if d is not None and d.allowed and not m.get("error"):
                guard.observe_output(m["tool_call"]["function"], text(m["content"]))
    return guard.stats()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", help="one injection_task_N.json (or none.json) from runs/")
    ap.add_argument("defense", choices=[*GUARD_DEFENSES, *(k for k, v in LEGACY_DEFENSE_NAMES.items() if v in GUARD_DEFENSES)],
                    metavar="DEFENSE", help="tracklimits, tracklimits_confirm_oracle, ... (old mcp_guard... names work too)")
    a = ap.parse_args()
    print(f"== {a.defense}: {a.log}")
    print("stats:", replay(a.log, a.defense))


if __name__ == "__main__":
    main()
