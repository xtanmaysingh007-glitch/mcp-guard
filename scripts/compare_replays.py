"""Compare two replay_frozen.py outputs (old guard vs fixed guard), call by call.

  python scripts/compare_replays.py old.json new.json [--md report.md]

Both files replay the same logs in the same order, so call i of a log lines up in both. A call counts as an
ATTACKER call if its arguments hold one of attribution.py's canaries (values only the injected text contains);
everything else counts as legitimate (this includes model mistakes and attacker steps with no canary, such as a
note to the user's own address: every newly blocked one is listed, so read the list).

Report per suite and replayed defense ("none as tracklimits" = a none log replayed under tracklimits):
  a) attacker calls blocked by both guards      b) attacker calls newly blocked
  c) legitimate calls newly blocked (listed)    d) calls newly ALLOWED (listed; should be none)
  e) cap notes (current guard only)
and, for clean logs (no injection), utility and prompts per task: logged utility, and "replay utility" = the log
solved the task AND the replayed guard refuses none of the calls that ran in it (a refused call would have broken
that run; it can't show tasks a guard would newly WIN).
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribution import CANARIES  # noqa: E402


def is_attacker(suite, call) -> bool:
    args = json.dumps(call["args"]).lower()
    return any(v.lower() in args and (tools is None or call["function"] in tools) for v, tools in CANARIES[suite])


def label(r) -> str:
    return r["defense"] if r["logged_defense"] == r["defense"] else f"{r['logged_defense']} as {r['defense']}"


def short(call) -> str:
    args = json.dumps(call["args"], ensure_ascii=False)
    return f"{call['function']}({args[:110]}{'...' if len(args) > 110 else ''})"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--json", help="write the summary here")
    a = ap.parse_args()
    old = json.loads(Path(a.old).read_text(encoding="utf-8"))
    new = json.loads(Path(a.new).read_text(encoding="utf-8"))
    assert len(old["replays"]) == len(new["replays"])

    rows = defaultdict(Counter)
    changed = defaultdict(list)        # key -> list of (kind, text)
    clean = defaultdict(lambda: defaultdict(Counter))  # key -> version -> counters
    for ro, rn in zip(old["replays"], new["replays"]):
        assert (ro["log"], ro["defense"]) == (rn["log"], rn["defense"]) and len(ro["calls"]) == len(rn["calls"])
        key = (rn["suite"], label(rn))
        c = rows[key]
        c["logs"] += 1
        for co, cn in zip(ro["calls"], rn["calls"]):
            c["calls"] += 1
            att = is_attacker(rn["suite"], cn)
            c["attacker calls"] += att
            c["asked old"] += co["asked"]
            c["asked new"] += cn["asked"]
            c["blocked old"] += not co["allowed"]
            c["blocked new"] += not cn["allowed"]
            where = f"{rn['log'].split('runs/')[-1].replace(chr(92), '/')}"
            if att:
                if not co["allowed"] and not cn["allowed"]:
                    c["a) attacker blocked both"] += 1
                elif co["allowed"] and not cn["allowed"]:
                    c["b) attacker newly blocked"] += 1
                    changed[key].append(("b", f"{short(cn)} | {cn['reason'][:140]} | {where}"))
                elif co["allowed"] and cn["allowed"]:
                    c["attacker allowed both"] += 1
            elif co["allowed"] and not cn["allowed"]:
                c["c) legit newly blocked"] += 1
                bad = "; ".join(f"{k}={v}" for k, v in cn["tainted"].items())
                changed[key].append(("c", f"{short(cn)} | arg {bad or '-'} | {cn['reason'][:160]} | "
                                          f"logged {cn['logged']} | {where}"))
            if not co["allowed"] and cn["allowed"]:
                c["d) newly allowed"] += 1
                changed[key].append(("d", f"{'ATTACKER ' if att else ''}{short(cn)} | old: {co['reason'][:140]} | "
                                          f"new asked={cn['asked']} | logged {cn['logged']} | {where}"))
            if co["asked"] != cn["asked"] and co["allowed"] == cn["allowed"]:
                c["ask changed only"] += 1
        if rn["injection_task"] is None:
            for ver, r in (("old", ro), ("new", rn)):
                k = clean[key][ver]
                k["tasks"] += 1
                k["logged utility"] += bool(r["utility"])
                broke = any(not x["allowed"] and x["logged"] in ("ran", "tool_error") for x in r["calls"])
                k["replay utility"] += bool(r["utility"]) and not broke
                k["prompts"] += sum(x["asked"] for x in r["calls"])
                k["blocks"] += sum(not x["allowed"] for x in r["calls"])

    for key in sorted(rows):
        c = rows[key]
        print(f"\n== {key[0]} / {key[1]}: {c['logs']} logs, {c['calls']} calls, {c['attacker calls']} attacker calls; "
              f"blocked {c['blocked old']} -> {c['blocked new']}, asked {c['asked old']} -> {c['asked new']}")
        print("   " + ", ".join(f"{k} {v}" for k, v in c.items() if k[:2] in ("a)", "b)", "c)", "d)")
                                 or k in ("attacker allowed both", "ask changed only")))
        for kind, t in changed[key]:
            print(f"   [{kind}] {t}")
        if key in clean:
            for ver in ("old", "new"):
                k = clean[key][ver]
                print(f"   clean {ver}: {k['tasks']} tasks, logged utility {k['logged utility']}, replay utility "
                      f"{k['replay utility']}, prompts {k['prompts']} ({k['prompts'] / k['tasks']:.2f}/task), "
                      f"blocks {k['blocks']}")
    print(f"\ncap notes (current guard): {len(new['caps'])}")
    for n in new["caps"][:20]:
        print("  ", n)
    if a.json:
        Path(a.json).write_text(json.dumps({
            "rows": {f"{s} / {d}": dict(c) for (s, d), c in sorted(rows.items())},
            "changed": {f"{s} / {d}": v for (s, d), v in sorted(changed.items())},
            "clean": {f"{s} / {d}": {ver: dict(k) for ver, k in v.items()} for (s, d), v in sorted(clean.items())},
            "caps": new["caps"]}, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
