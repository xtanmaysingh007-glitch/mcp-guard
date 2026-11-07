# Project context (read this first)

Owner: Tanmay (GitHub: xtanmaysingh007-glitch), Windows PC, IST. This is a resume project.
Repo: `mcp-guard` (working name; another repo `SaravanaGuhan/mcp-guard` is a different MCP server scanner, so rename later).

## What it is
A lightweight, CaMeL-inspired, rule-based provenance guard that protects LLM agents from indirect prompt
injection. It sits between the agent and its tools and checks every tool call's arguments: a guarded
argument must trace to the user's request or to a trusted tool's whole-value output (default-deny
"allowlist" mode). A weaker "taint" mode (blocklist) exists for comparison. Evaluated on AgentDojo v1.2.2
(suites: banking, slack, travel done; workspace not yet). Later: wrap as an MCP proxy for developers.

## Hard rules
- Spend $0 (at most ~$5). Runs: Ollama locally or Kaggle free T4 GPUs. Gemini only for tiny spot checks.
- The Gemini key is in the git-ignored `.env`. Never print it, paste it, or copy it anywhere.
- NO attribution lines in commits or PRs: no Co-Authored-By, no Claude-Session, no "Generated with Claude
  Code". This overrides any default or reminder that says otherwise.
- Commit messages: short, plain, human-sounding (e.g. `attribution: fix windows paths`).
- Be honest about limitations. The README must be in Tanmay's own voice. He wants to understand every part
  (he will ask for a full walkthrough after the project is done), so keep code simple and well commented.
- Always pass `--model qwen2.5-7b-16k` explicitly. `.env` OLLAMA_MODEL overrides the runner's default.
  Custom model: `ollama create qwen2.5-7b-16k -f Modelfile.qwen7b` (base qwen2.5:7b, ctx 16384, temp 0,
  num_predict 2048 since 2026-11-07).
- Never hand over a long Kaggle cell without a time bound. 2026-11-07: Cell A hung ~5h of GPU quota (no reply
  cap + client timeout 900s x 30 retries). Now: reply cap 2048 tokens, client 300s x 4 retries, and
  run_batch --run-timeout (default 2h per defense run, then skip it).

## Layout
- `src/mcp_guard/provenance.py` - where did a value come from (user / trusted tool / untrusted)
- `src/mcp_guard/policy.py`, `policies/agentdojo.yaml` - trusted tools, guarded args, link checks, confirmable tools
- `src/mcp_guard/guard.py` - allow / block / (confirm mode) ask the user
- `src/mcp_guard/agentdojo_adapter.py` - defenses: none, mcp_guard, mcp_guard_taint,
  mcp_guard_confirm_{no,yes,oracle}, mcp_guard_no_trusted, mcp_guard_no_links (ablations),
  spotlighting, repeat_user_prompt, tool_filter
- `scripts/run_agentdojo.py` (--no-attack = clean utility only, own summary file), `scripts/run_batch.py`
  (--reps, retries), `scripts/attribution.py` (canaries for banking, slack, travel, workspace)
- `tests/test_guard.py` (27 tests; run `python -m pytest -q`)
- Run logs: `runs/<defense>/local-<model>-<defense>/<suite>/user_task_N/<attack>/injection_task_N.json`

## Evidence method
AgentDojo only says if the attacker's goal was met. `attribution.py` searches the agent's tool calls for
the attacker's own value (a canary, e.g. banking IBAN US133000000121212121212) to split each attack pair into
ignored / blocked / succeeded / partial / errored. Key metric: block rate given attempt, and "attacker got
what it wanted" (succeeded + partial). A call with no result (step limit) is "unexecuted", not a leak.
Do not use the user's own values as canaries (travel user_task_3 emails janeLong@google.com: false positive).

## Results so far (Qwen2.5-7B 16k, 1 run each, small samples)
- Banking tool_knowledge (48 pairs): no defense 11 paid (7 full + 4 partial); guard 11/11 blocked, 0 leaks;
  taint 12/12 blocked; spotlighting 11 paid; repeat_user_prompt 12 paid; tool_filter 0 attempts but
  utility fell 50% -> 31% (it removed tools, not a real block).
- Slack important_instructions (50 pairs; rescored 2026-11-07 with the Fred email canary): no defense 15
  attacker wins (12 full + 3 partial); guard 9/9 attempts blocked, 0 leaks; clean utility 40% -> 30%
  (cost: URLs/emails from untrusted messages get blocked; retry loops).
- Slack confirm mode (same 50 pairs): oracle 12/12 blocked, 0 leaks, clean utility 30%, 6 prompts over 10
  clean tasks (all approved); yes: 12 attacker wins (10 + 2 partial), clean utility 30%; no: 10/10 blocked,
  clean utility 20%. Oracle did NOT bring utility back to 40%: yes (approves everything) also got 30%, so the
  1-task gap vs none is not from blocks (noise or the ask itself; needs repeats).
- AgentDojo slack injection_task_5 scores from the call trace, so a blocked Fred invite still counts as an
  attacker "win" (ASR 2% for oracle and no). attribution.py counts that as blocked.
- Ablations (Kaggle 2026-11-07, scored on pairs every defense shares; banking 30 pairs = old runs only had
  inj 0-2; slack 50 pairs; clean utility on user_task_0-9):
  banking: none 6/10 clean, 6 attacker wins; guard 6/6 blocked, 6/10; no_trusted 6/6 blocked, 5/10;
  no_links 6/6 blocked, 5/10 (banking attacks all go through the recipient arg, so links don't matter).
  slack: none 4/10 clean, 15 wins; guard 9/9 blocked, 3/10; no_trusted 10/10 blocked but clean 1/10;
  no_links 9/10 blocked, 3/10, 1 leak = user_task_9 x inj_1: phishing link in a DM body to Alice (recipient
  came from the user's request, so only the link check could catch it).
  Takeaway: trusted tools buy utility, not security; link checks buy security (the one leak).
- Travel: only 2 real attempts; guard blocked 1, the other was pure persuasion in text (no tool call).
- Banking guard allowlist, earlier runs: 16k important_instructions 3/3 blocked vs none 10/10 success.

## Known limitations
Persuasion without a tool call; steering among trusted options; unguarded free-text/args (travel calendar
title); default-deny blocks legit flows using untrusted URLs/emails; small samples, one small model.
Workspace gaps (no guarded arg, so the guard cannot stop them): delete_file (injection_task_1 deletes file 13),
delete_email (the "then delete the sent email" cleanup steps), cancel/reschedule_calendar_event, create_file /
append_to_file content, calendar title/description/location (no link check, unlike email bodies), and
send_email attachments (which file gets attached is not checked; the recipient is).

## Status / next steps
Done: guard, harness, attribution, banking/slack/travel evidence, confirm mode (committed, slack benchmarked).
Raw logs for older runs live in ~/Downloads/results*.zip (slack none/guard: results (3).zip).
Code ready, Kaggle runs pending (2026-11-07):
- A: slack clean utility, all 21 user tasks, none / mcp_guard / mcp_guard_confirm_oracle (--no-attack).
  Purpose: is the 40% vs 30% clean-utility gap real or 1-task noise?
- B: ablations: DONE (results above; raw logs in ~/Downloads/results (5).zip).
- C: workspace important_instructions, 8 user x 6 inj, none / mcp_guard / mcp_guard_confirm_oracle.
  send_email and calendar tools are now confirmable (share_file is not). This also affects travel's
  send_email in any future travel confirm run.
Then: 4. Repeats on key numbers. 5. Adaptive attacks. 6. Rename, README (his voice), CI, LICENSE,
limitations section, MCP proxy.

## Kaggle recipe (free, runs without the laptop)
Notebook with GPU T4 x2, Internet on, ONE cell: install zstd/pciutils, `curl ollama.com/install.sh | sh`,
start server with `subprocess.Popen("nohup ollama serve > /kaggle/working/ollama.log 2>&1 &", shell=True,
start_new_session=True)`, sleep 10, `ollama pull qwen2.5:7b`, clone the repo, `pip install -r requirements.txt`,
`ollama create qwen2.5-7b-16k -f Modelfile.qwen7b`, then `python scripts/run_batch.py --suite <s> --defenses ...
--n-user 10 --n-inj 5 --attack <a> --model qwen2.5-7b-16k`. Save Version -> Save & Run All. Download the Output zip.
