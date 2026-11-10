"""Run logs and secrets must never be committed: runs/ (raw benchmark logs) and .env (the Gemini key)."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which("git") is None or not (ROOT / ".git").exists(), reason="not a git checkout")
@pytest.mark.parametrize("path", ["runs/none/summary.json", "runs/_z16/ollama.log", ".env"])
def test_ignored_by_git(path):
    r = subprocess.run(["git", "check-ignore", "-q", path], cwd=ROOT)
    assert r.returncode == 0, f"{path} is not ignored by .gitignore"
