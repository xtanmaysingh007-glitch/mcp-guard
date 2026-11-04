"""Deprecated: use scripts/run_agentdojo.py. This just runs it with --defense none."""
import subprocess
import sys
from pathlib import Path

args = sys.argv[1:]
if "--defense" not in args:
    args += ["--defense", "none"]
sys.exit(subprocess.call([sys.executable, str(Path(__file__).with_name("run_agentdojo.py")), *args]))
