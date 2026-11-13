"""The guard files at HEAD mean the same as at the review-freeze tag (scripts/pin_guard.py): any drift since the tag is
comments / docstrings only. The M5 Kaggle cells run the same check and stop on a difference.

Needs git and the tag (CI checks out with full history and tags; on CI a missing tag is a failure, not a skip)."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pin_guard  # noqa: E402


def have_tag() -> bool:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        return False
    return subprocess.run(["git", "rev-parse", "-q", "--verify", f"{pin_guard.TAG}^{{commit}}"], cwd=ROOT,
                          capture_output=True).returncode == 0


def test_guard_files_match_review_freeze_up_to_comments():
    if not have_tag():
        if os.environ.get("CI"):
            pytest.fail(f"tag {pin_guard.TAG} not available on CI (checkout needs fetch-depth: 0)")
        pytest.skip(f"no git checkout with tag {pin_guard.TAG}")
    same = pin_guard.compare(pin_guard.TAG, None)          # the working tree, so uncommitted edits count too
    assert all(same.values()), {f: ok for f, ok in same.items() if not ok}


def test_structure_ignores_comments_and_docstrings_but_not_code():
    a = b'"""doc"""\nimport os\ndef f(x):\n    """one"""\n    return x + 1  # c\n'
    b = b'"""other doc"""\nimport os\n\n# new comment\ndef f(x):\n    """two"""\n    return x + 1\n'
    c = b'"""doc"""\nimport os\ndef f(x):\n    return x + 2\n'
    s = pin_guard.structure
    assert s("g.py", a) == s("g.py", b)
    assert s("g.py", a) != s("g.py", c)
    assert s("p.yaml", b"# one\nk: [a, b]\n") == s("p.yaml", b"k: [a, b]  # two\n")
    assert s("p.yaml", b"k: [a, b]\n") != s("p.yaml", b"k: [a]\n")


def test_hash_ignores_line_endings():
    files = {f: b"x\ny\n" for f in pin_guard.GUARD_FILES}
    crlf = {f: b"x\r\ny\r\n" for f in pin_guard.GUARD_FILES}
    assert pin_guard.files_hash(files.get) == pin_guard.files_hash(crlf.get)


def test_m5_code_is_outside_the_pinned_files():
    pinned = {Path(f).name for f in pin_guard.GUARD_FILES}
    assert not pinned & {"m5_tasks.py", "m5_spec.py", "run_agentdojo.py", "attribution.py"}
    for f in pin_guard.GUARD_FILES:
        text = (ROOT / f).read_text(encoding="utf-8")
        assert "m5" not in text.lower() and "real_model_name" not in text
