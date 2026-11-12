# Work in progress: fixing the independent review of edb44c6

Status file, so the work survives a context reset. Source: "TrackLimits: independent security review"
(2026-11-11, PDF in Downloads, 21 pages, findings R1 to R12). Its proof scripts were not in the repository (no
`review_poc/`), so every test rebuilds the proof from the written scenario.

## Order

1. Phase 1: strict xfail tests for R1 to R9, each confirmed failing on its security assertion.
2. Phase 2 (P0): whole-argument parsing, one result-recording path, strict policy loader, agentdojo.yaml fix,
   init quoting.
3. Phase 3 (P1): R2 rules, R8 caps, R9 exact case / keys, attribution fixes.
4. Phase 4: replay ALL frozen logs through the fixed guard (no live runs, no change to frozen folders).

## Done

| phase | commit | CI | what |
|---|---|---|---|
| 1 | `1ec319f` | green (8/8) | `tests/test_review_findings.py`: 25 strict xfail cases for R1-R9. Each failed on its assertion (checked with `--runxfail`); R1, R5 end to end on the real AgentDojo env, R3 end to end through the proxy. |
| 2 | `9a551d7` | green (8/8) | Guarded args parsed whole (`provenance.whole_atom`: email via `parseaddr` + strict pattern, URL via `urlsplit`, no userinfo / quotes / spaces, IBAN, else plain; empty or unparseable = never trusted; no 3-char minimum). `Guard.record_result(tool, args, output, is_error)` on every path (adapter, proxy, both replays, oracle audit). Strict `Policy.from_yaml` (+ `tool_args=`). agentdojo.yaml "#" restored. init JSON-quotes argument names. Approval docs corrected. |
| 3 | `96477a7` | green | R2: `secret_args` (a password must be a quoted token, exactly), request matches need >= 3 chars and a non-stop-word. R9: URLs lower-case scheme and host only; call approval key on exact strings. R8: caps (below) plus linear rewrites done before the cap decision. Attribution: "tool error" apart from "ran", `TRACE_SCORED` instead of the blanket override, `new_password` canary, disagreement list. |

| 4 | `a933fca`, `fe64dbd` (tag `review-freeze`) | green (8/8) | Replay of every frozen log, old guard (`1ec319f`) vs fixed, plus ground truth, argument coverage, clean utility / prompts: `docs/results_replay.md`. No attacker decision changed, nothing newly allowed, no ask changed, 38 new blocks (all model mistakes: empty recipient / hotel, recipient "me"), cap never hit; ground truth the same (0/809, travel 57/140). |

## Test status (after phase 3)

Full suite: 286 passed, 3 skipped, 14 xfailed. The 14: the 10 known gaps from before, and R4 in free text
(4 cases: an IP link, `ftp://`, `http:/`, a `.zip` bare domain in a message body), which is not in the plan.
Fixed and passing: R1, R2, R3, R4 (URL arguments), R5 x2, R6 x6, R7, R8 (+ cap test), R9 x3, R2 controls (banking
task 14's quoted password, a channel named in the request), 4 attribution self-tests.

## Decisions made so far

- **Proof scripts missing:** tests rebuilt from the PDF's scenarios; R7's needs the poisoned tool LAST in the
  list (PyYAML keeps the last duplicate key), which is the review's attack.
- **R9 query string moved into phase 2:** whole-argument parsing stopped extracting an email hidden in a URL's
  query, so a value-scope yes on the URL would have covered it. Approvals are keyed on the exact parsed value.
- **A "name" with a link / email / IBAN inside is unparseable** (adaptive case B2a regressed otherwise).
- **"bad" (unparseable) values are never trusted**, in every store (`_Values.contains` included).
- **record_result distrusts the call's OWN arguments per call**, not in the global written set: an agent that
  queries `get_users_in_channel("general")` before `get_channels` must still be able to use "general" later.
- **The untrusted corpus doesn't parse tokens whole** (cost); only the user's request does. Affects taint mode
  and audit labels only.
- **R8: caps instead of more optimizing** (Tanmay, 2026-11-12). Untrusted output is scanned as whitespace tokens of
  at most 2,048 chars; only the first 2,000 lines / 200,000 chars of trusted output become trusted values, the rest
  is recorded as untrusted (fail closed); documented in docs/settings.md. Already-done linear rewrites kept: email
  and spelled-out-email patterns start only at the beginning of a run (lookbehind, same matches), whitespace runs
  squeezed, bare domains found by a linear scan (0 mismatches against the old regex on 50,014 texts), base64
  decoding capped at 4 KB, the line-join check indexed, C YAML loader when available, `parseaddr` only for the
  `Name <addr>` form. Measured: 1 MB hostile output 0.2-0.9 s, trusted or not.
- **R2 stop words / minimum length:** `MIN_REQUEST_MATCH = 3`, a short English stop-word list (provenance.py).
  Applies to plain values matched against the request only; trusted tools' values are unaffected.
- **Approvals, what the code does:** the AgentDojo harness reuses a yes for the session (not one-time, no
  expiry); the proxy stores nothing and asks per call; `approve_call` (one use, TTL) has no caller but tests.
- **Strict loader:** unknown and duplicate keys, wrong shapes and an empty file raise; `policy_for` checks tool
  and argument names against the four suites (agentdojo.yaml passes). `unknown_tools` default NOT changed.

## Left

- **Phase 4: DONE** (see the table). Old guard taken as `1ec319f` = the commit before `9a551d7` (its guard code
  is `edb44c6`'s; it only adds the xfail tests).
- Optional live check: banking injection tasks 5-8 (never run live), none vs tracklimits, pinned to
  `review-freeze`. Travel has no held-out injections (only 0-6 exist, all run live already).
- adaptive_attacks.md final status line still to write.
- Not in this plan: R4 in free text, R10 (unchecked arguments: design), R11 (proxy trust anchors), R12 (audit log
  keeps passwords), the written set across sessions, README rewrite (draft pending from Tanmay).
