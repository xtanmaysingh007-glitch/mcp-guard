"""Guard: decides whether a tool call may run, given what the agent has seen so far."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .policy import Policy
from .provenance import Provenance


@dataclass
class Decision:
    allowed: bool
    tool: str
    reason: str = ""
    tainted: dict[str, list[str]] = field(default_factory=dict)  # arg -> offending atoms


class Guard:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.prov = Provenance()
        self.decisions: list[Decision] = []      # current session
        self.all_decisions: list[Decision] = []  # across sessions (for stats)
        self.n_sessions = 0

    def start_session(self, user_query: str) -> None:
        self.prov = Provenance()
        self.decisions = []
        self.prov.add_user(user_query)
        self.n_sessions += 1

    def observe_output(self, tool: str, output: str) -> None:
        if tool in self.policy.trusted_tools:
            self.prov.add_trusted(output)
        else:
            self.prov.add_untrusted(output)

    def check_call(self, tool: str, args: dict[str, Any]) -> Decision:
        bad: dict[str, list[str]] = {}
        checks = [(a, False) for a in self.policy.forbid_tainted.get(tool, [])]
        checks += [(a, True) for a in self.policy.check_links_in.get(tool, [])]  # free text: links only
        for arg, typed_only in checks:
            if arg in args:
                atoms = (self.prov.unverified_atoms(args[arg], typed_only) if self.policy.mode == "allowlist"
                         else self.prov.tainted_atoms(args[arg], typed_only))
                if atoms:
                    bad[arg] = atoms
        if bad:
            names = ", ".join(f"{a}={v}" for a, v in bad.items())
            d = Decision(False, tool, f"blocked: argument(s) not traceable to the user or a trusted source ({names}). "
                         "Only use values the user gave you or that come from trusted sources.", bad)
        else:
            d = Decision(True, tool)
        self.decisions.append(d)
        self.all_decisions.append(d)
        return d

    def stats(self) -> dict:
        blocked = [d for d in self.all_decisions if not d.allowed]
        by_tool: dict[str, int] = {}
        for d in blocked:
            by_tool[d.tool] = by_tool.get(d.tool, 0) + 1
        return {"sessions": self.n_sessions, "guarded_checks": len(self.all_decisions),
                "blocked": len(blocked), "blocked_by_tool": by_tool}
