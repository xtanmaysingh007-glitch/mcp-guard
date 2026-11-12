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
    assert set(built) == set(make_tables.SPECS) == {"slack", "banking", "ablations", "confirm", "workspace_f7r",
                                                    "workspace_f9", "banking_f10"}
    assert readme == built


def test_archive_info_is_pinned():
    archives = json.loads((ROOT / "results" / "archive.json").read_text(encoding="utf-8"))["archives"]
    assert [a["release_tag"] for a in archives] == ["logs-v1", "logs-v2"]
    # logs-v1 is published and must never change
    assert archives[0]["published"] is True
    assert archives[0]["sha256"] == "53f650e00f860aed3344d96756f96c909c33de05d8dc42d623e2926639fd62c4"
    for a in archives:
        assert len(a["sha256"]) == 64 and a["url"].endswith("/" + a["release_tag"] + "/" + a["asset"])
        assert isinstance(a["published"], bool)
