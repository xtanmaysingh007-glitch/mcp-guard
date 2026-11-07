"""Run AgentDojo on a model with a chosen defense (default: none = the 'before' numbers).

Reports (per suite):
  utility_no_attack      - fraction of normal tasks completed, no attacker present
  utility_under_attack   - fraction of normal tasks completed while under attack
  attack_success_rate    - fraction of (user task, injection task) pairs where the attacker's goal was achieved

Examples (PowerShell, from the project folder, venv active):
  python scripts/run_agentdojo.py --provider stub   --suite workspace --n-user 2 --n-inj 2   # offline smoke test
  python scripts/run_agentdojo.py --provider ollama --suite banking --defense none
  python scripts/run_agentdojo.py --provider ollama --suite banking --defense mcp_guard
  python scripts/run_agentdojo.py --provider ollama --suite slack --defense mcp_guard --no-attack   # clean utility only
  python scripts/run_agentdojo.py --provider ollama --suite workspace --user-tasks 13 25 33 --n-inj 6   # chosen tasks
Defenses: none, mcp_guard, mcp_guard_taint, mcp_guard_confirm_{no,yes,oracle},
  mcp_guard_no_trusted, mcp_guard_no_links (ablations), spotlighting, repeat_user_prompt, tool_filter
"""
import argparse
import json
import os
import threading
import time
from pathlib import Path  # noqa

import sys

import httpx
import openai
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from mcp_guard.agentdojo_adapter import DEFENSES, build_pipeline  # noqa: E402

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from agentdojo.functions_runtime import EmptyEnv
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import text_content_block_from_string
from agentdojo.functions_runtime import FunctionCall  # noqa: F401
from agentdojo.benchmark import TaskResults

# agentdojo 0.1.35 bug: loading cached results fails unless the model is rebuilt first
TaskResults.model_rebuild()

BENCH_VERSION = "v1.2.2"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"


class StubLLM(BasePipelineElement):
    """Does nothing useful. Only used to check the harness works offline."""

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        msg = {"role": "assistant", "content": [text_content_block_from_string("Done.")], "tool_calls": None}
        return query, runtime, env, [*messages, msg], extra_args


def make_throttled_client(rpm: float) -> httpx.Client:
    """httpx client that spaces requests out so we stay under a free-tier RPM limit."""
    lock, last = threading.Lock(), [0.0]
    min_gap = 60.0 / rpm

    def throttle(_request):
        with lock:
            wait = last[0] + min_gap - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            last[0] = time.monotonic()
        print(f"  [{time.strftime('%H:%M:%S')}] request sent", flush=True)

    def show_errors(response):
        # Print the server's reason for any error (429 and 5xx are retried automatically, but we still show why).
        if response.status_code >= 400:
            response.read()
            if response.status_code >= 500:
                print(f"[HTTP {response.status_code}] server busy, retrying...")
            elif response.status_code == 429:
                print(f"[HTTP 429] rate limited: {response.text[:700]}")
            else:
                print(f"\n[HTTP {response.status_code}] {response.text[:2000]}\n")

    return httpx.Client(event_hooks={"request": [throttle], "response": [show_errors]}, timeout=120)


def preflight_ollama(client, model: str) -> None:
    """Fail fast with a readable message instead of a 100-line traceback."""
    try:
        names = {m.id for m in client.models.list()}
    except Exception as e:  # connection refused etc.
        raise SystemExit(f"Cannot reach Ollama at {client.base_url} ({type(e).__name__}). "
                         "Start the Ollama app (or run `ollama serve`) and check `ollama list` works.")
    if model not in names and f"{model}:latest" not in names:
        raise SystemExit(f"Ollama is running but model '{model}' is not installed. Installed: {sorted(names)}. "
                         "Create it with: ollama create qwen2.5-7b-16k -f Modelfile.qwen7b")


def build_llm(provider: str, ollama_model: str | None = None):
    """Returns (llm_element, pipeline_name). The pipeline name must contain a key from
    agentdojo.models.MODEL_NAMES because attacks look up how to address the model by it.
    Folder names must also be valid on Windows (no ':')."""
    if provider == "stub":
        llm, name = StubLLM(), "local-stub"
    elif provider == "gemini":
        key = os.environ.get("GEMINI_API_KEY")
        if not key:
            raise SystemExit("GEMINI_API_KEY missing. Put it in .env (see .env.example).")
        model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        client = openai.OpenAI(
            api_key=key,
            base_url=GEMINI_BASE_URL,
            http_client=make_throttled_client(float(os.environ.get("GEMINI_RPM", "8"))),
            max_retries=12,
        )
        llm = OpenAILLM(client, model)
        # 'gemini-2.0-flash-001' suffix is only so AgentDojo addresses us as "AI model developed by Google".
        name = f"{model}__gemini-2.0-flash-001"
    elif provider == "ollama":
        model = ollama_model or os.environ.get("OLLAMA_MODEL", "qwen2.5-7b-16k")
        print(f"Using Ollama model: {model}", flush=True)
        client = openai.OpenAI(
            api_key="ollama",
            base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
            # A call that hangs is retried as-is, and at temperature 0 it hangs the same way again, so keep
            # timeout x retries small: worst case ~25 min, then the run crashes and run_batch resumes it.
            # (Ollama being briefly down is covered by run_batch's own retries, not by these.)
            timeout=300,
            max_retries=4,
        )
        preflight_ollama(client, model)
        llm = OpenAILLM(client, model)
        name = "local-" + model.replace(":", "-")  # 'local' key -> "Local model"
    else:
        raise SystemExit(f"unknown provider {provider}")
    llm.name = name
    return llm, name


def rate(d: dict) -> float | None:
    return round(sum(d.values()) / len(d), 4) if d else None


def main():
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", choices=["stub", "gemini", "ollama"], required=True)
    ap.add_argument("--suite", choices=["workspace", "slack", "banking", "travel"], default="workspace")
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--defense", choices=DEFENSES, default="none")
    ap.add_argument("--model", default=None, help="Ollama model name (overrides .env), e.g. qwen2.5-7b-16k")
    ap.add_argument("--n-user", type=int, default=None, help="only first N user tasks (saves API quota)")
    ap.add_argument("--user-tasks", nargs="+", default=None, metavar="N",
                    help="only these user tasks, by number (e.g. 4 13 25); pick them with scripts/injectable_tasks.py")
    ap.add_argument("--n-inj", type=int, default=None, help="only first N injection tasks")
    ap.add_argument("--skip-clean", action="store_true", help="skip the no-attack utility run")
    ap.add_argument("--no-attack", action="store_true", help="only the clean utility run (no injection tasks)")
    ap.add_argument("--rerun", action="store_true", help="ignore cached logs")
    ap.add_argument("--rep", type=int, default=1, help="repeat number; rep 2+ logs to runs/<defense>/rep<N> so it doesn't reuse the cache")
    args = ap.parse_args()
    if args.no_attack and args.skip_clean:
        ap.error("--no-attack and --skip-clean together would run nothing")

    llm, name = build_llm(args.provider, args.model)
    pipeline, guard = build_pipeline(llm, name, args.defense)
    suite = get_suite(BENCH_VERSION, args.suite)
    user_tasks = sorted(suite.user_tasks, key=lambda t: int(t.split("_")[-1]))[: args.n_user]
    if args.user_tasks and args.n_user is not None:
        ap.error("use --n-user or --user-tasks, not both")
    if args.user_tasks:
        # accept "13" or "user_task_13"; keep the suite's own order so runs are comparable
        wanted = {f"user_task_{int(t.split('_')[-1])}" for t in args.user_tasks}
        unknown = wanted - set(suite.user_tasks)
        if unknown:
            ap.error(f"not in {args.suite}: {sorted(unknown)}")
        user_tasks = [t for t in user_tasks if t in wanted]
    inj_tasks = sorted(suite.injection_tasks, key=lambda t: int(t.split("_")[-1]))[: args.n_inj]
    logdir = Path("runs") / args.defense
    if args.rep > 1:
        logdir = logdir / f"rep{args.rep}"
    logdir.mkdir(parents=True, exist_ok=True)
    out = {"model": name, "defense": args.defense, "suite": args.suite, "attack": args.attack, "rep": args.rep, "user_tasks": user_tasks, "injection_tasks": inj_tasks}

    with OutputLogger(str(logdir), live=None):
        if not args.skip_clean:
            clean = benchmark_suite_without_injections(
                pipeline, suite, logdir, args.rerun, user_tasks=user_tasks, benchmark_version=BENCH_VERSION
            )
            out["utility_no_attack"] = rate(clean["utility_results"])
            # per task, so two defenses can be compared on the same tasks (keys are (user_task, ""))
            out["utility_no_attack_by_task"] = {k[0]: bool(v) for k, v in clean["utility_results"].items()}
            if guard is not None:
                # Counts only tasks that actually ran in THIS process (cached tasks are skipped by AgentDojo).
                out["guard_no_attack"] = guard.stats()
                guard.reset_stats()

        if not args.no_attack:
            attack = load_attack(args.attack, suite, pipeline)
            res = benchmark_suite_with_injections(
                pipeline, suite, attack, logdir, args.rerun,
                user_tasks=user_tasks, injection_tasks=inj_tasks, verbose=False, benchmark_version=BENCH_VERSION,
            )
    if not args.no_attack:
        out["utility_under_attack"] = rate(res["utility_results"])
        # AgentDojo convention: security_results[...] is True when the ATTACKER's goal was achieved.
        out["attack_success_rate"] = rate(res["security_results"])
        out["n_pairs"] = len(res["security_results"])
        if guard is not None:
            out["guard_under_attack"] = guard.stats()
    else:
        out["attack"] = None
        out["injection_tasks"] = []

    # clean-only runs get their own file name, so they never overwrite an attacked run's summary
    attack_label = "no_attack" if args.no_attack else args.attack
    summary = logdir / f"summary_{name}_{args.suite}_{attack_label}_{args.defense}.json"
    summary.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    print(f"\nSaved {summary}")


if __name__ == "__main__":
    main()
