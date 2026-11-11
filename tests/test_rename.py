"""The rename mcp-guard -> TrackLimits (2026-11-11) must not orphan the frozen results.

Frozen run folders and logs keep their old defense names (mcp_guard, mcp_guard_confirm_oracle, ...). Every entry
point that takes a defense name accepts the old names too and maps them to the new ones (tracklimits,
tracklimits_confirm_oracle, ...), so old logs can still be replayed and old commands still run.
"""
import json
import sys
from pathlib import Path

import pytest

from tracklimits.agentdojo_adapter import DEFENSES, LEGACY_DEFENSE_NAMES, build_pipeline, policy_for, resolve_defense

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def test_every_guard_defense_has_its_old_name():
    guard = [d for d in DEFENSES if d.startswith("tracklimits")]
    assert guard and all(d.replace("tracklimits", "mcp_guard", 1) in LEGACY_DEFENSE_NAMES for d in guard)
    assert resolve_defense("mcp_guard") == "tracklimits"
    assert resolve_defense("mcp_guard_confirm_oracle") == "tracklimits_confirm_oracle"
    assert resolve_defense("mcp_guard_confirm_oracle_trust_full") == "tracklimits_confirm_oracle_trust_full"
    assert resolve_defense("none") == "none" and resolve_defense("tracklimits_taint") == "tracklimits_taint"
    with pytest.raises(ValueError):
        resolve_defense("no_such_defense")


def test_old_names_work_in_the_adapter():
    assert policy_for("mcp_guard_confirm_oracle") == policy_for("tracklimits_confirm_oracle")
    assert policy_for("mcp_guard_taint").mode == "taint"
    pipeline, guard = build_pipeline(type("L", (), {"name": "local-x", "query": None})(), "local-x", "mcp_guard")
    assert guard is not None and pipeline.name == "local-x-tracklimits"


def test_run_batch_passes_the_new_name(monkeypatch):
    import run_batch
    cmds = []
    monkeypatch.setattr(run_batch.subprocess, "call", lambda cmd, **kw: cmds.append(cmd) or 0)
    monkeypatch.setattr(run_batch, "unload_models", lambda: None)
    monkeypatch.setattr(sys, "argv", ["run_batch.py", "--defenses", "none", "mcp_guard", "mcp_guard_confirm_oracle"])
    run_batch.main()
    assert [c[c.index("--defense") + 1] for c in cmds] == ["none", "tracklimits", "tracklimits_confirm_oracle"]


def test_run_agentdojo_accepts_old_names():
    import run_agentdojo
    assert {"mcp_guard", "mcp_guard_confirm_oracle"} <= set(run_agentdojo.DEFENSE_CHOICES)


def test_replay_an_old_log_with_its_old_defense_name(capsys):
    import replay_guard
    log = ROOT / "tests" / "fixtures" / "ws_user_task_4_none.json"
    old = replay_guard.replay(str(log), "mcp_guard")
    new = replay_guard.replay(str(log), "tracklimits")
    assert old == new and old["guarded_checks"] > 0


def test_attribution_labels_old_folder_names(tmp_path, monkeypatch, capsys):
    import attribution
    d = tmp_path / "runs" / "mcp_guard" / "local-m-mcp_guard" / "workspace" / "user_task_0" / "important_instructions"
    d.mkdir(parents=True)
    (d / "injection_task_0.json").write_text(json.dumps({"messages": [{"role": "user", "content": "x"}]}))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["attribution.py", "--suite", "workspace", "--model", "local-m"])
    attribution.main()
    assert "mcp_guard (= tracklimits) rep1" in capsys.readouterr().out
