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
  Custom model: `ollama create qwen2.5-7b-16k -f Modelfile.qwen7b` (base qwen2.5:7b, ctx 16384, temp 0).

## Layout
- `src/mcp_guard/provenance.py` - where did a value come from (user / trusted tool / untrusted)
- `src/mcp_guard/policy.py`, `policies/agentdojo.yaml` - trusted tools, guarded args, link checks, confirmable tools
- `src/mcp_guard/guard.py` - allow / block / (confirm mode) ask the user
- `src/mcp_guard/agentdojo_adapter.py` - defenses: none, mcp_guard, mcp_guard_taint,
  mcp_guard_confirm_{no,yes,oracle}, spotlighting, repeat_user_prompt, tool_filter
- `scripts/run_agentdojo.py`, `scripts/run_batch.py` (--reps, retries), `scripts/attribution.py`
- `tests/test_guard.py` (24 tests; run `python -m pytest -q`)
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
- Travel: only 2 real attempts; guard blocked 1, the other was pure persuasion in text (no tool call).
- Banking guard allowlist, earlier runs: 16k important_instructions 3/3 blocked vs none 10/10 success.

## Known limitations
Persuasion without a tool call; steering among trusted options; unguarded free-text/args (travel calendar
title); default-deny blocks legit flows using untrusted URLs/emails; small samples, one small model.

## Status / next steps
Done: guard, harness, attribution, banking/slack/travel evidence, confirm mode (committed, slack benchmarked).
Raw logs for older runs live in ~/Downloads/results*.zip (slack none/guard: results (3).zip).
Next, in order:
2. Workspace suite. 3. Ablations (policy.without_trusted_tools / without_link_checks). 4. Repeats on key
numbers. 5. Adaptive attacks. 6. Rename, README (his voice), CI, LICENSE, limitations section, MCP proxy.

## Kaggle recipe (free, runs without the laptop)
Notebook with GPU T4 x2, Internet on, ONE cell: install zstd/pciutils, `curl ollama.com/install.sh | sh`,
start server with `subprocess.Popen("nohup ollama serve > /kaggle/working/ollama.log 2>&1 &", shell=True,
start_new_session=True)`, sleep 10, `ollama pull qwen2.5:7b`, clone the repo, `pip install -r requirements.txt`,
`ollama create qwen2.5-7b-16k -f Modelfile.qwen7b`, then `python scripts/run_batch.py --suite <s> --defenses ...
--n-user 10 --n-inj 5 --attack <a> --model qwen2.5-7b-16k`. Save Version -> Save & Run All. Download the Output zip.
