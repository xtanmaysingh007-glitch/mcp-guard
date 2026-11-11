# TrackLimits

Provenance-based prompt injection defense for LLM agent tool calls.

Formerly mcp-guard.

A security proxy that protects MCP-based AI agents from indirect prompt injection, evaluated on the
AgentDojo benchmark (ETH Zurich, NeurIPS 2024).

**Status:** guard core + AgentDojo integration done; offline results in `docs/results_replay.md`; real-model runs next.

## Setup (Windows PowerShell)

```powershell
cd "C:\Prompt Injection"
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # if blocked: Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements.txt
copy .env.example .env
notepad .env                      # paste your Gemini key after GEMINI_API_KEY=
```

## 1. Offline smoke test (no key, no cost)

```powershell
python scripts/run_agentdojo.py --provider stub --suite workspace --n-user 2 --n-inj 2
```
Expect all zeros - the stub model does nothing. It just proves the harness runs.

## 2. Tiny Gemini run (free tier)

```powershell
python scripts/run_agentdojo.py --provider gemini --suite workspace --n-user 2 --n-inj 2
```
Throttled by `GEMINI_RPM` in `.env`. If you get 429 errors, lower it or switch `GEMINI_MODEL`
to one that is free in your AI Studio dashboard.

## 3. Local model (Ollama) - main workhorse

Free hosted tiers (Gemini: 20 requests/day) are far too small for a full AgentDojo run, so development
and bulk runs use a local model. AgentDojo prompts are long, so we raise Ollama's context window:

```powershell
winget install Ollama.Ollama
ollama pull qwen2.5:7b
ollama create qwen2.5-7b-16k -f Modelfile.qwen7b
# in .env set: OLLAMA_MODEL=qwen2.5-7b-16k
python scripts/run_agentdojo.py --provider ollama --suite banking --n-user 2 --n-inj 2 --defense none
python scripts/run_agentdojo.py --provider ollama --suite banking --n-user 2 --n-inj 2 --defense tracklimits
```

## Compute plan
1. Ollama (local Qwen): development + bulk runs.
2. One small paid run on a hosted model (hard spend cap, ~$5 max) for headline numbers.
3. Free Gemini tier: tiny spot-checks only.

Results are saved to `runs/<defense>/summary_*.json` (git-ignored).

Defenses: `none`, `tracklimits` (allowlist), `tracklimits_taint`, `spotlighting`, `repeat_user_prompt`, `tool_filter`.

## Offline evaluation (no model needed)

```powershell
python scripts/replay_ground_truth.py --mode allowlist --suites banking
python -m pytest -q
```

Results before the rename (2026-11-11) use the old defense names: `mcp_guard` = `tracklimits`,
`mcp_guard_confirm_oracle` = `tracklimits_confirm_oracle`, and so on (`mcp_guard...` -> `tracklimits...`).
The frozen run folders and logs keep the old names; every script accepts both.
