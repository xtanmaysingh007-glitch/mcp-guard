"""Run several defenses back to back, and keep going if Ollama (or the network) hiccups.

AgentDojo caches every finished task in runs/<defense>/..., so re-running a failed command only
redoes the unfinished tasks. This wrapper loops until each run completes (or gives up).

  python scripts/run_batch.py --suite banking --defenses none mcp_guard
  python scripts/run_batch.py --suite workspace --defenses none mcp_guard --n-inj 3
  python scripts/run_batch.py --suite banking --defenses none mcp_guard --reps 3 --attack tool_knowledge
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="ollama")
    ap.add_argument("--suite", default="banking")
    ap.add_argument("--defenses", nargs="+", default=["none", "mcp_guard"])
    ap.add_argument("--model", default=None, help="passed through to run_agentdojo.py")
    ap.add_argument("--reps", type=int, default=1, help="run each defense this many times")
    ap.add_argument("--max-attempts", type=int, default=6)
    ap.add_argument("--wait", type=int, default=60, help="seconds to wait before retrying a failed run")
    args, extra = ap.parse_known_args()

    status = {}
    for rep in range(1, args.reps + 1):
      for d in args.defenses:
        key = f"{d} rep{rep}"
        for attempt in range(1, args.max_attempts + 1):
            print(f"\n=== {args.suite} / {key} (attempt {attempt}/{args.max_attempts}) ===", flush=True)
            rc = subprocess.call([sys.executable, str(HERE / "run_agentdojo.py"), "--provider", args.provider,
                                  "--suite", args.suite, "--defense", d, "--rep", str(rep),
                                  *(["--model", args.model] if args.model else []), *extra])
            if rc == 0:
                status[key] = "done"
                break
            print(f"run exited with code {rc}; waiting {args.wait}s then resuming from cache...", flush=True)
            time.sleep(args.wait)
        else:
            status[key] = "FAILED"
    print("\n=== summary ===")
    for d, s in status.items():
        print(f"{d}: {s}")
    print("results: runs/<defense>/summary_*.json")


if __name__ == "__main__":
    main()
