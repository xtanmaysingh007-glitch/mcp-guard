"""`python -m mcp_guard init`: a policy skeleton from an MCP server's tool list."""
import json

import pytest
import yaml

from mcp_guard.guard import Guard
from mcp_guard.init_policy import load_tool_list, main, skeleton
from mcp_guard.policy import Policy

TOOLS_LIST = {   # what an MCP server answers to tools/list
    "tools": [
        {"name": "send_email", "description": "Send an email.\nUse with care.",
         "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}},
        {"name": "search_docs", "description": "Search the docs: by keyword # or tag",
         "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
        {"name": "delete-page", "inputSchema": {"type": "object"}},
    ]
}
NAMES = ["send_email", "search_docs", "delete-page"]


def write(tmp_path, data, name="tools.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.mark.parametrize("data", [TOOLS_LIST, {"jsonrpc": "2.0", "id": 1, "result": TOOLS_LIST},
                                  NAMES, TOOLS_LIST["tools"]], ids=["tools/list", "jsonrpc", "names", "tool-list"])
def test_load_tool_list_accepts_common_shapes(tmp_path, data):
    assert [t["name"] for t in load_tool_list(write(tmp_path, data))] == NAMES


def test_skeleton_lists_every_tool_as_unclassified_and_blocks_them(tmp_path):
    out = tmp_path / "policy.yaml"
    out.write_text(skeleton(load_tool_list(write(tmp_path, TOOLS_LIST))), encoding="utf-8")
    data = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert data["unclassified"] == NAMES
    assert data["unknown_tools"] == "block"
    policy = Policy.from_yaml(out)                     # a valid policy, loadable as is
    assert policy.unknown_tools == "block" and policy.known_tools() == set()
    g = Guard(policy)
    g.start_session("anything")
    assert not any(g.check_call(name, {}).allowed for name in NAMES)   # nothing runs until classified


def test_skeleton_explains_each_section():
    text = skeleton([{"name": "x"}])
    for section in ("safe_tools", "forbid_tainted", "confirmable", "always_confirm", "trusted_tools"):
        assert f"# {section}:" in text, section
    assert "args: to, body" in skeleton(TOOLS_LIST["tools"])      # argument names shown as a hint


def test_cli_writes_file_and_refuses_to_overwrite(tmp_path):
    src, out = write(tmp_path, TOOLS_LIST), tmp_path / "policy.yaml"
    assert main(["init", str(src), "-o", str(out)]) == 0
    assert yaml.safe_load(out.read_text(encoding="utf-8"))["unclassified"] == NAMES
    with pytest.raises(SystemExit):
        main(["init", str(src), "-o", str(out)])                 # exists: needs --force
    assert main(["init", str(src), "-o", str(out), "--force"]) == 0
