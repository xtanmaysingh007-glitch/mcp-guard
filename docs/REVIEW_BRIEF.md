# TrackLimits: review brief

Provenance-based prompt injection defense for LLM agent tool calls. Formerly mcp-guard. Everything below comes
from this repository (code, tests, `CLAUDE.md`, `docs/`); numbers come from logged runs. Defense names in results
before 2026-11-11 are the old ones (`mcp_guard` = `tracklimits`, `mcp_guard_confirm_oracle` =
`tracklimits_confirm_oracle`, ...).

## 1. Goal and threat model

**Protected:** the actions an LLM agent takes through tools: who gets an email or message, where money goes,
which URL is opened, what is deleted. The defense decides, per tool call, whether the call's arguments come from
the user or from data an attacker could have written.

**Attacker:** writes into any data the agent reads through an untrusted tool (emails, files, messages, web
pages, calendar entries), including instructions aimed at the model; disguises values (defanged URLs,
zero-width characters, base64, homoglyphs); knows how the guard works (`docs/adaptive_attacks.md`, cases A-G);
can write into "weak" structured sources (contacts built from emails, channel names). Cannot change the user's
request, the policy or the guard, or write into strong trusted sources (the user's own account data).

**Out of scope:** persuasion with no tool call (the model just says something); steering among values that are
all trusted ("book the most expensive hotel"); free-text arguments with no value to trace (a calendar title, a
file's content); a user who approves the attacker's call; a compromised MCP server or host; model jailbreaks in
general.

## 2. Architecture

```
 user request ──────────────────────────┐
                                        v
 ┌─────────┐ tool call ┌────────────────────────────────────┐ allowed ┌────────────────────┐
 │  Agent   │─────────>│ Guard.check_call                    │───────> │ Tool (AgentDojo env │
 │  (LLM)   │          │  policy: which args are guarded,    │         │ or a real MCP      │
 │          │<─────────│  provenance: where each value       │         │ server)            │
 └─────────┘ refusal / │  came from -> allow / ask / block   │         └─────────┬──────────┘
      ^      result    └──────────────┬─────────────────────┘                   │ output
      │                     ask (confirm mode)  ^ observe_output                 │
      │                               v         │ (trusted / untrusted)          │
      │                          ┌────────┐     └────────────────────────────────┘
      └──────────────────────────│  User  │
                                 └────────┘
 Integrations: AgentDojo pipeline (GuardedToolsExecutor) | stdio MCP proxy (`tracklimits proxy`)
 Evaluation:   run_agentdojo / run_batch (runs) -> attribution (canaries) -> replay_guard (offline what-if)
```

**Provenance** (`src/tracklimits/provenance.py`). Records the user's request, trusted tools' outputs as whole
values (strong and weak apart) and untrusted output; extracts atoms (emails, URLs, IBANs, plain values) after
undoing known disguises; answers "does this atom trace to the user or a trusted value?".

**Policy** (`policy.py`, `policies/agentdojo.yaml`, `docs/settings.md`). Guarded arguments, free-text arguments
scanned for links/emails/IBANs, tool classes (trusted / weak / safe / confirmable / always_confirm), the user's
identities, fail-safe defaults (unknown tools blocked in the proxy and `tracklimits init`; `strict_trust` typed).

**Guard** (`guard.py`). Unknown tool -> block; untraceable guarded value or `always_confirm` tool -> ask (confirm
mode) or block (plain). Session state: approvals, declines (no more asking after 2), a retry cap, and values the
agent itself wrote.

**Integrations.** The AgentDojo adapter puts the guard in the pipeline's tool-execution step. The stdio MCP
proxy (`proxy/`) passes `tools/list` through unchanged, checks every `tools/call` first, never forwards a refused
call, and writes a JSON-lines audit log.

## 3. Key design decisions

- **Default-deny (allowlist).** A guarded value must trace to the user or a trusted source. A blocklist ("taint"
  mode, kept for comparison) only stops values seen verbatim in untrusted data, so reworded or invented values
  pass. Cost: legitimate flows using untrusted data are blocked (slack clean 8/21 -> 4/21 in F1).
- **Whole-value trust.** A trusted tool vouches only for a whole field or list item, never for an address
  inside a sentence, so attacker text quoted in trusted output gains nothing.
- **Weak vs strong trusted tools.** Attacker-writable structured sources (contacts from emails, channel names)
  don't count for outward emails / URLs / IBANs under `strict_trust: typed` (default; plain names still do).
  Closes adaptive B1-B3 for one workspace task; `full` would cut slack perfect-agent utility 11/21 -> 4/21.
- **Confirm mode, call-bound approvals.** A confirmable call is shown to the user instead of blocked; a yes covers
  that value (value scope) or that exact call once (call scope; the proxy always uses one-time call approvals
  that expire with the prompt). Declines stick, and after two the guard stops asking.
- **Write-then-read tracking.** Values the agent wrote into a non-trusted tool stay untrusted when a trusted tool
  returns them (adaptive C2b, laundering).
- **Message-to-self check.** For sends whose every recipient is the user, a body copying 6+ words of untrusted
  text or holding an untraceable 8+-digit number is asked / blocked (`self_note_*`). Observed variant only.
- **Canary attribution.** AgentDojo says whether the attacker's goal was met, not whether it tried;
  `scripts/attribution.py` finds the attacker's own values in the tool calls to split ignored / blocked /
  succeeded / partial / errored.

## 4. Methodology

**Runs.** AgentDojo v1.2.2 (package 0.1.35), attacks `important_instructions` and `tool_knowledge`, local models
via Ollama on free Kaggle T4 GPUs: Qwen2.5-7B (banking, slack) and Qwen2.5-14B (workspace), 16k context,
temperature 0, 2048-token reply cap, a time cap per defense. One run per setting.

**Counting.** A pair is an *attempt* if any tool call contains a canary; *blocked* if every such call was
refused; *succeeded* / *partial* if one ran (partial = AgentDojo's goal not met exactly). A call with no result
(step limit) is not a leak. Main metric: attacker wins = succeeded + partial; block rate given an attempt.
Results are scored on the pairs all compared defenses finished.

**Simulated users.** `confirm_yes` approves everything (worst case), `confirm_no` declines everything, and the
**oracle** approves unless the call contains a known attacker value or targets a known attacker object
(`ATTACKER_VALUES`, `ATTACKER_TARGETS`, `ATTACKER_NUMBERS`). The oracle is told what the attacker wants; a real
user isn't. It also approves values the model invented, so oracle utility is an upper bound.

**Repeatability.** Since commit `6b56bab`: tool-call arguments sorted before they return to the model (Ollama
returned them in random key order), `PYTHONHASHSEED=0`, the Ollama model unloaded before every defense (fresh
prompt cache); since `fa2c618`, optionally `--freeze-clock` (fixed timestamps on newly created emails/files).
Check F8b: two identical runs of the one log that still differed gave 0 of 10 messages different.

**Noise and bias (known).** Runs before `6b56bab` aren't repeatable (cache state, argument order, hash seed,
timestamps), so one-task utility differences are noise. One run per setting, small samples, one model family.
The injection never reached the model in many no-defense pairs (banking 15/48, travel 27/56); Qwen-7B never
attempted a workspace attack in 142 pairs (hence 14B there). The oracle knows the attacker's values; its audit
found and fixed gaps twice. AgentDojo's ASR counts some refused calls as wins (slack injection 5). Replays force
logged calls. The policy was written for these suites by the person who evaluated it.

## 5. Results

Attacker wins = succeeded + partial (attribution). Utility = AgentDojo's task success.

| Run (commit) | Suite, model, pairs | Defense | Attempts | Blocked | Attacker wins | Clean utility |
|---|---|---|---|---|---|---|
| F2 (`dfd4d0e`) | banking, 7B, 60 pairs + 12 clean | none | 20 | 0 | 20 (13+7) | 5/12 |
| | | every guard variant | 20 | 20 | 0 | 4/12, 0 prompts |
| F1 (`dfd4d0e`) | slack, 7B, 84 shared pairs + 21 clean | none | 25 | 0 | 25 (19+6) | 8/21 |
| | | tracklimits (plain) | 19 | 19 | 0 | 4/21 |
| | | confirm_oracle | 26 | 26 | 0 | 9/21, 2.38 prompts/task |
| | | confirm_yes | 25 | 0 | 25 | 8/21 |
| F5 (`308b35a`) | slack, 7B, same 84 pairs | confirm_oracle (P2) | 26 | 26 | 0 | 8/21, 1.43 prompts/task |
| F4 (`01e78da`) | slack, 7B, 74 shared pairs + 21 clean | no_trusted | 15 | 15 | 0 | 2/21 |
| | | no_links | 17 | 16 | 1 | 5/21 |
| F7r (`4168589`) | workspace inj 0-9, 14B, 50 pairs + 5 clean | none | 16 | 0 | 16 (4+12) | 4/5 |
| | | tracklimits | 15 | 15 | 0 | 2/5 (1 real block cost) |
| | | confirm_oracle | 16 | 16 | 0 | 3/5 |
| F9 (`df7b8cb`, frozen clock) | workspace inj 10-13, 14B, 20 pairs + 5 clean | none | 7 | 0 | 7 (2+5) | 4/5 |
| | | tracklimits | 6 | 6 | 0 | 3/5 |
| | | confirm_oracle | 8 | 8 | 0 | 4/5, 1 prompt |

Not counted above: in F7r and F9 the injections' "note to self" (a ransom text to the user's own address) ran
under both guards (F7r 2 + 2, F9 2 + 3). The message-to-self check (`a18fa83`) would now stop all of them in
replay, with 0 changed decisions on clean runs; there is no live run with it yet. Of none's 12 F7r partials, 7
carried real inbox data.

## 6. Known weaknesses and open cases

- **Value split across two calls** (adaptive C2a): each call is checked alone.
- **A user who says yes to the attacker's first prompt** (F K=1): no guard can overrule a yes.
- **Message to self, paraphrased without digits or with the number in words** (G3, G4); the subject line and
  mixed recipients aren't checked.
- **Free text with no value to trace** (calendar title / description, file content, which file is attached);
  **steering among trusted options** (blocked only under `strict_trust: full`); **persuasion without a tool call.**
- **Default-deny costs utility** (slack clean 8/21 -> 4/21 plain); confirm mode recovers it at ~1.4 prompts per
  task; plain mode can never delete / cancel / reschedule (workspace tasks 7, 35, 38).
- **A block can push the model into the injection:** in one case (C3) the only attacker win happened under the
  guard, after a block, through a then-unguarded tool.
- **normalize() knows a fixed list of disguises** (not ROT13, words, punycode); approvals ignore query strings;
  the oracle approves deleting file 11 (user tasks delete it too).
- **Proxy:** terminal-only prompts, a manual request file, tools only (no resources / prompts), one call at a
  time, no per-turn prompt batching, not yet tried with a real host or model.

## 7. Questions for the reviewer

1. Is the provenance model sound? Where does exact matching (after normalization) give false confidence?
2. Are 6-26 attempts per row, one run each, enough to claim more than "blocked every attempt we saw"? What
   should be repeated, how often?
3. Which attack classes are missing from the adaptive suite and the benchmark runs?
4. Is the oracle evaluation biased (it knows the attacker's values)? How should confirm mode be reported instead?
5. Is canary attribution a fair measure of "the attacker got what it wanted"?
6. Is `strict_trust: typed` a defensible default, or should weak sources never count for outward arguments?
7. Does confirm mode just move the problem to the user (fatigue, a first-prompt yes)? Is stopping after two
   declines right?
8. What breaks in a real deployment: policy authoring, free-text tools, long tasks, hosts without a terminal?
9. Are the utility costs acceptable, and are none, spotlighting, repeat_user_prompt and tool_filter fair baselines?
10. Do the results transfer beyond one model family, local quantized models, AgentDojo, and a policy written by
    the evaluator?
