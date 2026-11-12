"""scripts/make_tables.py: README table blocks, and the README matching the tables last built from the archive.

The full rebuild from the release archive runs in CI's agentdojo job (make_tables.py --check README.md), once
results/archive.json says the archive is published.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import make_tables  # noqa: E402


def test_replace_fills_empty_and_full_blocks_and_round_trips():
    text = "a\n<!-- table:x -->\n<!-- /table:x -->\nb\n<!-- table:y -->\nold\n<!-- /table:y -->\n"
    out = make_tables.replace(text, {"x": "| 1 |", "y": "| 2 |\n| 3 |"})
    assert make_tables.blocks(out) == {"x": "| 1 |", "y": "| 2 |\n| 3 |"}
    assert make_tables.replace(out, make_tables.blocks(out)) == out
    assert out.startswith("a\n") and "\nb\n" in out


def test_readme_tables_match_the_last_archive_build():
    readme = make_tables.blocks((ROOT / "README.md").read_text(encoding="utf-8"))
    built = make_tables.blocks((ROOT / "results" / "tables.md").read_text(encoding="utf-8"))
    assert set(built) == {"slack", "banking", "ablations", "confirm", "workspace_f7r", "workspace_f9"}
    assert readme == built


def test_archive_info_is_pinned():
    info = json.loads((ROOT / "results" / "archive.json").read_text(encoding="utf-8"))
    assert len(info["sha256"]) == 64 and info["url"].endswith(info["asset"]) and isinstance(info["published"], bool)
