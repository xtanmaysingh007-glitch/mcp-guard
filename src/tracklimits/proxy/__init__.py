"""MCP proxy: puts the guard between an MCP host and a real MCP server. See docs/proxy.md."""
from .confirm import TerminalConfirm, format_prompt, terminal_available
from .core import GuardedProxy, load_proxy_policy, read_request

__all__ = ["GuardedProxy", "TerminalConfirm", "format_prompt", "load_proxy_policy", "read_request",
           "terminal_available"]
