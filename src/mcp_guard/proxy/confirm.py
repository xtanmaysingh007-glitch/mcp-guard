"""Asking the user about a held tool call, in a terminal.

The proxy's stdin and stdout belong to the MCP protocol (the host talks to us through them), so the prompt
can't use them. It opens the terminal directly instead: /dev/tty on Linux / macOS, the console (CONOUT$ and
msvcrt) on Windows. A host that starts the proxy with no terminal at all (most desktop apps) can't show a
prompt this way; then the proxy runs with confirm "none" and just blocks.

Only "y" or "yes" approves. Anything else, or no answer before the timeout, is a no.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Callable


def format_prompt(tool: str, args: dict, bad: dict[str, list[str]]) -> str:
    """What the user sees: the tool, the exact arguments that will be sent, and why they are being asked."""
    lines = ["", "=== mcp-guard: a tool call is waiting for your OK ===",
             f"tool: {tool}",
             "arguments (exactly what will be sent if you approve):",
             json.dumps(args, indent=2, ensure_ascii=False)]
    if bad:
        lines.append("why you are asked: these values are not traceable to your request or a trusted tool:")
        lines += [f"  {arg}: {', '.join(atoms)}" for arg, atoms in bad.items()]
    else:
        lines.append("why you are asked: the policy says this tool always needs your OK (always_confirm)")
    lines.append("If you did not ask for this, say no. Approve this one call? [y/N] ")
    return "\n".join(lines)


class TerminalConfirm:
    """confirm_fn for the Guard: show the prompt, wait up to `timeout` seconds for an answer.
    read_line(timeout) -> str | None (None = no answer in time) and write(text) can be swapped for tests."""

    def __init__(self, timeout: float = 120, read_line: Callable[[float], str | None] | None = None,
                 write: Callable[[str], None] | None = None):
        self.timeout = timeout
        if read_line is None or write is None:
            term_read, term_write = open_terminal()
            read_line, write = read_line or term_read, write or term_write
        self.read_line, self.write = read_line, write

    def __call__(self, tool: str, args: dict, bad: dict[str, list[str]]) -> bool:
        self.write(format_prompt(tool, args, bad))
        answer = self.read_line(self.timeout)
        if answer is None:
            self.write(f"\nno answer in {self.timeout:g} s: the call is declined.\n")
            return False
        ok = answer.strip().lower() in ("y", "yes")
        self.write("approved (this one call only)\n" if ok else "declined\n")
        return ok


def terminal_available() -> bool:
    try:
        open_terminal()
        return True
    except OSError:
        return False


def open_terminal() -> tuple[Callable[[float], str | None], Callable[[str], None]]:
    """(read_line, write) on the controlling terminal. Raises OSError if there is none."""
    if os.name == "nt":
        return _windows_console()
    return _posix_tty()


def _posix_tty():
    import select
    tty = open("/dev/tty", "r+", encoding="utf-8")   # OSError if the process has no terminal

    def write(text: str) -> None:
        tty.write(text)
        tty.flush()

    def read_line(timeout: float) -> str | None:
        ready, _, _ = select.select([tty], [], [], timeout)
        return tty.readline() if ready else None

    return read_line, write


def _windows_console():
    import msvcrt
    out = open("CONOUT$", "w", encoding="utf-8")       # OSError if the process has no console

    def write(text: str) -> None:
        out.write(text)
        out.flush()

    def read_line(timeout: float) -> str | None:
        # msvcrt reads the console keyboard directly, even though our stdin is the MCP pipe
        deadline, buf = time.monotonic() + timeout, ""
        while time.monotonic() < deadline:
            if msvcrt.kbhit():
                ch = msvcrt.getwche()
                if ch in "\r\n":
                    write("\n")
                    return buf
                buf = buf[:-1] if ch == "\b" else buf + ch
            else:
                time.sleep(0.05)
        return None

    return read_line, write


def stderr_note(text: str) -> None:
    """Notes for whoever runs the proxy (the host usually logs our stderr)."""
    print(f"mcp-guard proxy: {text}", file=sys.stderr, flush=True)
