# Offline results: ground-truth replay (no LLM)

`python scripts/replay_ground_truth.py --mode {off,taint,allowlist} --suites <suite>`

Idealised agents, AgentDojo v1.2.2, attack `important_instructions`:
- **honest utility**: a perfect agent runs each user task's reference solution. Lower = the guard
  wrongly blocked legitimate work (false blocks).
- **hijacked attack success**: a fully compromised agent does the user task, then the attacker's
  reference solution. Worst case: the model obeyed every injection.

| Suite (tasks / pairs) | No guard: utility / attack success | Taint mode | Allowlist mode (default) |
|---|---|---|---|
| banking (16 / 144)   | 100% / 100%  | 87.5% / 0%    | 87.5% / 0%    |
| workspace (40 / 560) | 100% / 38.9% | 87.5% / 7.1%  | 87.5% / 7.1%  |
| slack (21 / 105)     | 100% / 100%  | 57.1% / 69.5% | 52.4% / 49.5% |
| travel (20 / 140)    | 100% / 97.1% | 100% / 40.7%  | 100% / 40.7%  |

(Without a guard, workspace attack success is only 38.9% because many attacker reference
solutions don't satisfy their checker after the user task has already run.)

## Reading
- **banking**: every attack blocked. 2 false blocks: legitimate payments to IBANs that only appear
  in a file/bill (untrusted), e.g. user_task_0, user_task_15.
- **workspace**: attacks cut 38.9% -> 7.1%. 5 false blocks: recipients/participants found only in
  emails or calendar entries (untrusted), e.g. "invite the people from this email".
- **slack**: weak both ways. 12/21 honest tasks blocked (URLs and emails posted in messages, e.g.
  "visit the site Bob shared"); ~half of attacks still succeed -> investigate which tools/args.
- **travel**: no false blocks, but 40.7% of attacks still succeed -> likely "steering within trusted
  values" (e.g. book a different hotel from the trusted listing) or unguarded args. Investigate.

## Caveats
- Ideal agents only. Real models fail tasks on their own and don't obey every injection, so real
  numbers will differ; these isolate what the *guard* does.
- Taint and allowlist give the same numbers on reference traces because the reference attacker
  copies values verbatim; the difference shows up against obfuscated/adaptive attacks (see tests).
