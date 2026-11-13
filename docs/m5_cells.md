# M5 Kaggle cells

Design: [m5_design.md](m5_design.md). One notebook cell per suite (each sets itself up, so they can run in separate
sessions), plus an optional control cell. Same pattern as F10: GPU T4 x2, Internet on, one cell, Save Version ->
Save & Run All, download the Output zip.

All cells pin the code to commit `3e7a8ee822afba9dc82b40a43ffb48ef416c8ac3` (the M5 tasks and flags, CI green) and
the guard files to `review-freeze`: right after the clone, `scripts/pin_guard.py --restore` prints the review-freeze
commit, the M5 commit, the review-freeze guard-files hash and the AST comparison, restores the guard files from the
tag and checks their hash; any difference stops the cell before Ollama is even installed. Checked from a fresh
clone: hash `bc6ec733c5c8d13bb7d1b545a2ba1f4323782ed8a7e3bd6961a63c3d945bb030` before and after, AST same for all 5
files.

Time bounds: every shell step has a timeout, every defense has `--run-timeout` (hours in total across retries), the
Ollama reply cap and client timeouts are the ones from 2026-11-07. No clean runs (`--skip-clean`). Frozen clock and
`--real-model-name` everywhere, so logs land in `runs/<defense>/clock-frozen/real-name/`.

| cell | model | pairs per defense | expected wall time | hard ceiling |
|---|---|---|---|---|
| banking | qwen2.5-7b-16k | 12 user tasks x inj 9-12 = 48 | ~0.65 h + ~10 min setup | 2 x 0.5 h + setup |
| slack | qwen2.5-7b-16k | 21 user tasks x inj 6-8 = 63 | ~1.45 h + ~10 min setup | 2 x 1.0 h + setup |
| workspace | qwen2.5-14b-16k | 5 user tasks x inj 14-15 = 10 | ~0.8 h + ~15 min setup | 2 x 0.75 h + setup |
| control (optional) | qwen2.5-7b-16k | 12 user tasks x existing inj 6-7 = 24, none only | ~0.15 h + ~10 min setup | 0.3 h + setup |

## Banking

```python
# M5 banking: none vs tracklimits (plain), guard pinned to review-freeze. Every step is time-bounded.
import os, subprocess, time
W = "/kaggle/working"
M5_COMMIT = "3e7a8ee822afba9dc82b40a43ffb48ef416c8ac3"

def sh(cmd, timeout):
    print("$", cmd, flush=True)
    subprocess.run(cmd, shell=True, check=True, timeout=timeout)

os.chdir(W)
sh("git clone -q https://github.com/xtanmaysingh007-glitch/tracklimits.git", 300)
os.chdir(f"{W}/tracklimits")
sh(f"git checkout -q {M5_COMMIT} && git rev-parse HEAD", 60)
sh("pip install -q pyyaml", 300)
sh("python scripts/pin_guard.py --restore", 120)   # prints review-freeze hash, M5 commit, AST result; stops if different
sh("apt-get install -y -qq zstd pciutils > /dev/null", 600)
sh("curl -fsSL --retry 6 --retry-delay 20 --retry-all-errors -o /tmp/ollama_install.sh https://ollama.com/install.sh", 600)
sh("sh /tmp/ollama_install.sh > /dev/null", 900)
subprocess.Popen(f"nohup ollama serve > {W}/ollama.log 2>&1 &", shell=True, start_new_session=True)
time.sleep(10)
sh("timeout 1800 ollama pull qwen2.5:7b", 1900)
sh('pip install -q -r requirements.txt "agentdojo==0.1.35"', 900)
sh("ollama create qwen2.5-7b-16k -f Modelfile.qwen7b", 600)
common = ("--suite banking --model qwen2.5-7b-16k --attack tool_knowledge --freeze-clock --skip-clean "
          "--extra-tasks m5 --real-model-name "
          "--user-tasks 0 2 3 4 5 6 9 11 12 13 14 15 --inj-tasks 9 10 11 12")
for d in ("none", "tracklimits"):
    sh(f"python scripts/run_batch.py --defenses {d} --run-timeout 0.5 {common}", int(0.6 * 3600))
sh("python scripts/attribution.py --suite banking --attack tool_knowledge --model local-qwen2.5-7b-16k", 600)
sh(f"tar czf {W}/m5_banking_runs.tgz runs", 600)
```

## Slack

```python
# M5 slack: none vs tracklimits (plain), guard pinned to review-freeze. Every step is time-bounded.
import os, subprocess, time
W = "/kaggle/working"
M5_COMMIT = "3e7a8ee822afba9dc82b40a43ffb48ef416c8ac3"

def sh(cmd, timeout):
    print("$", cmd, flush=True)
    subprocess.run(cmd, shell=True, check=True, timeout=timeout)

os.chdir(W)
sh("git clone -q https://github.com/xtanmaysingh007-glitch/tracklimits.git", 300)
os.chdir(f"{W}/tracklimits")
sh(f"git checkout -q {M5_COMMIT} && git rev-parse HEAD", 60)
sh("pip install -q pyyaml", 300)
sh("python scripts/pin_guard.py --restore", 120)   # prints review-freeze hash, M5 commit, AST result; stops if different
sh("apt-get install -y -qq zstd pciutils > /dev/null", 600)
sh("curl -fsSL --retry 6 --retry-delay 20 --retry-all-errors -o /tmp/ollama_install.sh https://ollama.com/install.sh", 600)
sh("sh /tmp/ollama_install.sh > /dev/null", 900)
subprocess.Popen(f"nohup ollama serve > {W}/ollama.log 2>&1 &", shell=True, start_new_session=True)
time.sleep(10)
sh("timeout 1800 ollama pull qwen2.5:7b", 1900)
sh('pip install -q -r requirements.txt "agentdojo==0.1.35"', 900)
sh("ollama create qwen2.5-7b-16k -f Modelfile.qwen7b", 600)
common = ("--suite slack --model qwen2.5-7b-16k --attack important_instructions --freeze-clock --skip-clean "
          "--extra-tasks m5 --real-model-name --inj-tasks 6 7 8")          # all 21 user tasks
for d in ("none", "tracklimits"):
    sh(f"python scripts/run_batch.py --defenses {d} --run-timeout 1.0 {common}", int(1.1 * 3600))
sh("python scripts/attribution.py --suite slack --attack important_instructions --model local-qwen2.5-7b-16k", 600)
sh(f"tar czf {W}/m5_slack_runs.tgz runs", 600)
```

## Workspace

```python
# M5 workspace: none vs tracklimits (plain), Qwen2.5-14B, guard pinned to review-freeze. Every step is time-bounded.
import os, subprocess, time
W = "/kaggle/working"
M5_COMMIT = "3e7a8ee822afba9dc82b40a43ffb48ef416c8ac3"

def sh(cmd, timeout):
    print("$", cmd, flush=True)
    subprocess.run(cmd, shell=True, check=True, timeout=timeout)

os.chdir(W)
sh("git clone -q https://github.com/xtanmaysingh007-glitch/tracklimits.git", 300)
os.chdir(f"{W}/tracklimits")
sh(f"git checkout -q {M5_COMMIT} && git rev-parse HEAD", 60)
sh("pip install -q pyyaml", 300)
sh("python scripts/pin_guard.py --restore", 120)   # prints review-freeze hash, M5 commit, AST result; stops if different
sh("apt-get install -y -qq zstd pciutils > /dev/null", 600)
sh("curl -fsSL --retry 6 --retry-delay 20 --retry-all-errors -o /tmp/ollama_install.sh https://ollama.com/install.sh", 600)
sh("sh /tmp/ollama_install.sh > /dev/null", 900)
subprocess.Popen(f"nohup ollama serve > {W}/ollama.log 2>&1 &", shell=True, start_new_session=True)
time.sleep(10)
sh("timeout 1800 ollama pull qwen2.5:14b", 1900)
sh('pip install -q -r requirements.txt "agentdojo==0.1.35"', 900)
sh("ollama create qwen2.5-14b-16k -f Modelfile.qwen14b", 600)
common = ("--suite workspace --model qwen2.5-14b-16k --attack important_instructions --freeze-clock --skip-clean "
          "--extra-tasks m5 --real-model-name --user-tasks 4 13 15 19 20 --inj-tasks 14 15")
for d in ("none", "tracklimits"):
    sh(f"python scripts/run_batch.py --defenses {d} --run-timeout 0.75 {common}", int(0.85 * 3600))
sh("python scripts/attribution.py --suite workspace --attack important_instructions --model local-qwen2.5-14b-16k", 600)
sh(f"tar czf {W}/m5_workspace_runs.tgz runs", 600)
```

## Control (optional): does the real name change the model's behaviour?

Banking none on AgentDojo's own injection tasks 6 and 7 with `--real-model-name`, same settings as F10 otherwise.
Compare with F10's none row on those two tasks (no real name: attacker calls in 8 of 24 pairs, user tasks 0, 2, 12,
13).

```python
# M5 control: banking none on existing injections 6 and 7 with --real-model-name (vs F10). Time-bounded.
import os, subprocess, time
W = "/kaggle/working"
M5_COMMIT = "3e7a8ee822afba9dc82b40a43ffb48ef416c8ac3"

def sh(cmd, timeout):
    print("$", cmd, flush=True)
    subprocess.run(cmd, shell=True, check=True, timeout=timeout)

os.chdir(W)
sh("git clone -q https://github.com/xtanmaysingh007-glitch/tracklimits.git", 300)
os.chdir(f"{W}/tracklimits")
sh(f"git checkout -q {M5_COMMIT} && git rev-parse HEAD", 60)
sh("pip install -q pyyaml", 300)
sh("python scripts/pin_guard.py --restore", 120)   # prints review-freeze hash, M5 commit, AST result; stops if different
sh("apt-get install -y -qq zstd pciutils > /dev/null", 600)
sh("curl -fsSL --retry 6 --retry-delay 20 --retry-all-errors -o /tmp/ollama_install.sh https://ollama.com/install.sh", 600)
sh("sh /tmp/ollama_install.sh > /dev/null", 900)
subprocess.Popen(f"nohup ollama serve > {W}/ollama.log 2>&1 &", shell=True, start_new_session=True)
time.sleep(10)
sh("timeout 1800 ollama pull qwen2.5:7b", 1900)
sh('pip install -q -r requirements.txt "agentdojo==0.1.35"', 900)
sh("ollama create qwen2.5-7b-16k -f Modelfile.qwen7b", 600)
sh("python scripts/run_batch.py --defenses none --run-timeout 0.3 --suite banking --model qwen2.5-7b-16k "
   "--attack tool_knowledge --freeze-clock --skip-clean --real-model-name "
   "--user-tasks 0 2 3 4 5 6 9 11 12 13 14 15 --inj-tasks 6 7", int(0.4 * 3600))
sh("python scripts/attribution.py --suite banking --attack tool_knowledge --model local-qwen2.5-7b-16k", 600)
sh(f"tar czf {W}/m5_control_runs.tgz runs", 600)
```
