"""Replay EVERY frozen AgentDojo log through one version of the guard, with no model, and save each decision.

Used for the review's phase 4: run it once with the old guard's src/ and once with the current one, then
compare the two JSON files with scripts/compare_replays.py. Frozen folders are only read, never written.

  python scripts/replay_frozen.py --out old.json --src <old checkout>/src
  python scripts/replay_frozen.py --out new.json                      # this checkout's src/

What gets replayed:
- every log under runs/ (user_task_*/.../*.json), once per unique content (runs/_z16/tgz and runs/_z16/mcp-guard
  hold the same files twice); the stub / Gemini baselines are skipped;
- a log recorded under a guard defense is replayed under that defense (old mcp_guard... names resolve);
- a log recorded under any other defense (none, spotlighting, ...) is replayed under tracklimits AND
  tracklimits_confirm_oracle, to see what the guard would do with the calls a less defended model made.

Each logged tool call is checked in order, the way the live adapter of that guard version does it: the output of
a call is recorded only if the replayed guard allows the call and the log has a real result for it (a call that
was refused in the original run has no output in the log). Same caveat as replay_guard.py: the calls are forced
from the log, so a replay can't show what the model would do after a NEW refusal.

The current guard also reports trusted outputs that went past the trusted-output cap (provenance.TRUSTED_MAX_*)
and untrusted tokens longer than UNTRUSTED_TOKEN_CAP; the old guard had no caps.
"""
import argparse
import hashlib
import json
import re
import sys
import time
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_RE = re.compile(r"^local-(qwen2\.5-\d+b(?:-16k)?|llama3\.1-8b(?:-16k)?)-(.+)$")


def text(content) -> str:
    """AgentDojo stores message content as a list of {"type": "text", "content": ...} blocks."""
    if isinstance(content, list):
        return "".join(b.get("content") or "" for b in content)
    return str(content or "")


def unique_logs(runs: Path) -> list[Path]:
    """All logs, one path per distinct content (sorted, so the same path wins on every run)."""
    seen, out = set(), []
    for p in sorted(runs.rglob("*.json")):
        if not any(part.startswith("user_task_") for part in p.parts):
            continue
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        if h not in seen:
            seen.add(h)
            out.append(p)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--src", default=str(ROOT / "src"), help="the src/ folder of the guard version to replay")
    ap.add_argument("--runs", default=str(ROOT / "runs"))
    a = ap.parse_args()
    warnings.filterwarnings("ignore")

    sys.path.insert(0, a.src)
    from tracklimits import provenance                                             # noqa: E402
    from tracklimits.agentdojo_adapter import (CONFIRM_USERS, GUARD_DEFENSES,      # noqa: E402
                                               policy_for, resolve_defense)
    from tracklimits.guard import Guard                                            # noqa: E402
    assert Path(provenance.__file__).resolve().is_relative_to(Path(a.src).resolve()), provenance.__file__

    # Cap instrumentation (current guard only): note every trusted output cut at the cap, and long untrusted tokens.
    caps, ctx = [], {}
    if hasattr(provenance, "TRUSTED_MAX_CHARS"):
        Prov = provenance.Provenance
        orig_trusted, orig_untrusted = Prov.add_trusted, Prov.add_untrusted

        def add_trusted(self, text_, *args, **kw):
            head = "".join(text_.splitlines(keepends=True)[:provenance.TRUSTED_MAX_LINES])[:provenance.TRUSTED_MAX_CHARS]
            if len(head) < len(text_):
                caps.append({**ctx, "kind": "trusted output past the cap", "chars": len(text_),
                             "lines": text_.count("\n") + 1})
            return orig_trusted(self, text_, *args, **kw)

        def add_untrusted(self, text_):
            long = [t for t in text_.split() if len(t) > provenance.UNTRUSTED_TOKEN_CAP]
            if long:
                caps.append({**ctx, "kind": "untrusted token past the cap", "tokens": len(long),
                             "longest": max(map(len, long))})
            return orig_untrusted(self, text_)

        Prov.add_trusted, Prov.add_untrusted = add_trusted, add_untrusted

    def record(guard, call, out, is_error):
        if hasattr(guard, "record_result"):        # current guard: one path, errors never trusted
            guard.record_result(call["function"], dict(call.get("args") or {}), out, is_error=is_error)
        else:                                      # old guard: what its adapter did (output + error text)
            guard.observe_output(call["function"], out)

    logs = unique_logs(Path(a.runs).resolve())
    results, skipped, t0 = [], 0, time.time()
    for p in logs:
        d = json.loads(p.read_text(encoding="utf-8"))
        m = MODEL_RE.match(d.get("pipeline_name") or "")
        msgs = d.get("messages") or []
        if not m or not msgs:
            skipped += 1
            continue
        logged = resolve_defense(m.group(2))
        replays = [logged] if logged in GUARD_DEFENSES else ["tracklimits", "tracklimits_confirm_oracle"]
        user = next((text(x["content"]) for x in msgs if x["role"] == "user"), "")
        tool_msgs = {x["tool_call_id"]: x for x in msgs if x["role"] == "tool"}
        for defense in replays:
            guard = Guard(policy_for(defense), confirm_fn=CONFIRM_USERS.get(defense))
            guard.start_session(user)
            ctx.update(log=str(p.relative_to(ROOT)), defense=defense)
            calls = []
            for x in msgs:
                if x["role"] != "assistant":
                    continue
                for c in x.get("tool_calls") or []:
                    ctx["tool"] = c["function"]
                    dec = guard.check_call(c["function"], dict(c.get("args") or {}))
                    res = tool_msgs.get(c["id"])
                    err = (res.get("error") or "") if res else None
                    status = ("unexecuted" if res is None else "blocked" if err.startswith("blocked:")
                              else "tool_error" if err else "ran")
                    calls.append({"function": c["function"], "args": c.get("args") or {}, "logged": status,
                                  "allowed": dec.allowed, "asked": dec.asked, "approved": dec.approved,
                                  "reason": dec.reason, "tainted": dec.tainted})
                    if dec.allowed and status in ("ran", "tool_error"):
                        out = text(res["content"]) if not err else f"{text(res['content'])}\n{err}"
                        record(guard, res.get("tool_call") or c, out, bool(err))
            results.append({"log": str(p.relative_to(ROOT)), "suite": d["suite_name"], "logged_defense": logged,
                            "defense": defense, "model": m.group(1), "user_task": d["user_task_id"],
                            "injection_task": d.get("injection_task_id"), "attack": d.get("attack_type"),
                            "utility": d.get("utility"), "security": d.get("security"), "calls": calls})
    Path(a.out).write_text(json.dumps({"src": a.src, "logs": len(logs), "skipped": skipped,
                                       "replays": results, "caps": caps}), encoding="utf-8")
    print(f"{len(logs)} unique logs ({skipped} skipped), {len(results)} replays, {len(caps)} cap notes, "
          f"{time.time() - t0:.0f} s -> {a.out}")


if __name__ == "__main__":
    main()
