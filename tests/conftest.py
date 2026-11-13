"""Lets the core tests run without the AgentDojo extra (CI's core job installs only `.[proxy,test]`).

Files that import AgentDojo at the top are left out when it isn't installed; single tests that need it carry
@pytest.mark.agentdojo and are skipped. With `pip install -e ".[proxy,agentdojo,test]"` everything runs.
"""
import importlib.util

import pytest

HAVE_AGENTDOJO = importlib.util.find_spec("agentdojo") is not None
AGENTDOJO_FILES = ["test_adaptive.py", "test_executor.py", "test_executor_parity.py", "test_freeze_clock.py",
                   "test_oracle_audit.py", "test_repeat_limit.py", "test_repeatability.py", "test_rename.py", "test_review_findings.py", "test_m5.py"]
collect_ignore = [] if HAVE_AGENTDOJO else AGENTDOJO_FILES


def pytest_configure(config):
    config.addinivalue_line("markers", "agentdojo: needs the agentdojo extra (pip install -e \".[agentdojo]\")")


def pytest_collection_modifyitems(config, items):
    if HAVE_AGENTDOJO:
        return
    skip = pytest.mark.skip(reason="needs the agentdojo extra: pip install -e \".[agentdojo]\"")
    for item in items:
        if item.get_closest_marker("agentdojo"):
            item.add_marker(skip)
