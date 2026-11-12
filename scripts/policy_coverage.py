"""Which arguments of the AgentDojo tools does the policy actually check? No model, no environment.

  python scripts/policy_coverage.py

Every tool of the four AgentDojo v1.2.2 suites is either read-only (safe_tools / trusted_tools: nothing to
guard) or ACTING. Each argument of an acting tool is put in exactly one bucket, first match wins:
  traced        forbid_tainted: the value must trace to the request or a trusted tool (secret_args: the
                password must be a quoted token of the request; listed apart)
  link-checked  check_links_in: free text, only the links / emails / IBANs inside it must trace
  self-note     self_note_tools only (body of a note to the user's own address: copy / digit checks)
  confirm-only  the tool is always_confirm (IDs that can't be traced: every call goes to the user)
  unchecked     nothing looks at it
"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from tracklimits.agentdojo_adapter import policy_for  # noqa: E402


def bucket(p, tool, arg) -> str:
    if arg in p.secret_args.get(tool, []):
        return "traced (secret)"
    if arg in p.forbid_tainted.get(tool, []):
        return "traced"
    if arg in p.check_links_in.get(tool, []):
        return "link-checked"
    if arg in p.self_note_tools.get(tool, []):
        return "self-note"
    if tool in p.always_confirm:
        return "confirm-only"
    return "unchecked"


def main():
    p = policy_for("tracklimits")
    read_only = p.safe_tools | p.trusted_tools
    total = Counter()
    for suite in ("banking", "slack", "travel", "workspace"):
        rows, per = [], Counter()
        for f in get_suite("v1.2.2", suite).tools:
            if f.name in read_only:
                per["read-only tools"] += 1
                continue
            per["acting tools"] += 1
            for arg in f.parameters.model_fields:
                b = bucket(p, f.name, arg)
                per[b] += 1
                rows.append(f"    {f.name}.{arg}: {b}")
        total.update(per)
        print(f"== {suite}: " + ", ".join(f"{k} {v}" for k, v in per.items()))
        print("\n".join(rows))
    print("== all suites (a tool shared by two suites counts twice): " + ", ".join(f"{k} {v}" for k, v in total.items()))


if __name__ == "__main__":
    main()
