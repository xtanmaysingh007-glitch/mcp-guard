"""Guard: decides whether a tool call may run, given what the agent has seen so far."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Callable

from .policy import Policy
from .provenance import Provenance, call_canonical, canonical, canonical_value, iter_strings, primary_atom

# A plainly blocked call gets the normal "not traceable" reason this many times; any further identical
# try gets "already refused, stop". (Confirm mode already stops after the user's first "no".)
PLAIN_BLOCK_RETRIES = 2
# Circuit breaker (confirm mode): after the user has declined this many calls in a session, stop asking and
# block every untraceable value for the rest of the session. A session that keeps producing calls the user
# refuses is probably under attack, and every extra prompt is a chance for a tired "yes".
MAX_DECLINES = 2


@dataclass
class Decision:
    allowed: bool
    tool: str
    reason: str = ""
    tainted: dict[str, list[str]] = field(default_factory=dict)  # arg -> offending atoms
    asked: bool = False       # confirm mode: the user was shown this call
    approved: bool = False    # ... and said yes


class Guard:
    def __init__(self, policy: Policy, confirm_fn: Callable[[str, dict, dict], bool] | None = None):
        """confirm_fn(tool, args, offending_atoms) -> bool. None = never ask, just block (default)."""
        self.policy = policy
        self.confirm_fn = confirm_fn
        self.prov = Provenance()
        self.decisions: list[Decision] = []      # current session
        self.all_decisions: list[Decision] = []  # across sessions (for stats)
        self.n_sessions = 0
        self._reset_session_state()

    def _reset_session_state(self) -> None:
        self.refused: dict[str, int] = {}        # call key -> times the USER declined it this session
        self.blocked_times: dict[str, int] = {}  # call key -> times plainly blocked this session
        # Approvals are scoped: a yes covers that exact value in that argument of that tool, nothing more.
        # (They used to become "user-given" everywhere, so approving a link also approved an IBAN inside it.)
        self.approved: set[tuple[str, str, str]] = set()  # (tool, arg, canonical atom)
        self.approved_calls: set[str] = set()             # EXACT call keys the user said yes to
        self.declines = 0                                 # calls the user declined this session
        # approval_scope "call": approvals given ahead of the call (approve_call), one use each, with expiry
        self.call_approvals: dict[str, int] = {}          # approval key -> last call number it is valid for
        self.n_calls = 0                                  # calls checked this session (the expiry clock)

    def start_session(self, user_query: str) -> None:
        self.prov = Provenance()
        self.decisions = []
        self._reset_session_state()
        self.prov.add_user(user_query)
        # The user's own identity (e.g. their email address) is something they "said" in every session,
        # even when the request doesn't spell it out. Exact match only, like any typed value.
        for identity in self.policy.user_identities:
            self.prov.add_user(identity)
        self.n_sessions += 1

    def observe_output(self, tool: str, output: str) -> None:
        if tool in self.policy.trusted_tools:
            self.prov.add_trusted(output, weak=tool in self.policy.weak_trusted_tools)
        else:
            self.prov.add_untrusted(output)

    @staticmethod
    def _call_key(tool: str, args: dict[str, Any]) -> str:
        """Exact key: used for "the user already said yes to exactly this call"."""
        return tool + json.dumps(args, sort_keys=True, default=str)

    @staticmethod
    def _retry_key(tool: str, args: dict[str, Any]) -> str:
        """Canonical key: used for "already declined / already blocked", so a cosmetic variant of a refused
        call (upper case, trailing slash, ?x=1, no www) counts as the same call."""
        return tool + json.dumps(canonical_value(args), sort_keys=True, default=str)

    @staticmethod
    def approval_key(tool: str, args: dict[str, Any]) -> str:
        """Call-scoped approval key: a hash of the tool name and ALL its arguments (canonical)."""
        raw = tool + json.dumps(call_canonical(args), sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def approve_call(self, tool: str, args: dict[str, Any]) -> str:
        """Record a yes for this exact call before the agent makes it (e.g. a proxy that blocks, shows the
        user the call, and lets the agent retry once approved). Valid once, for the next approval_ttl_calls
        checked calls. Returns the key."""
        key = self.approval_key(tool, args)
        self.call_approvals[key] = self.n_calls + self.policy.approval_ttl_calls
        return key

    def _use_call_approval(self, tool: str, args: dict[str, Any]) -> bool:
        """True (and the approval is used up) if a stored, unexpired approval covers exactly this call."""
        expires = self.call_approvals.pop(self.approval_key(tool, args), None)
        return expires is not None and self.n_calls <= expires

    def _untraceable(self, tool: str, args: dict[str, Any]) -> dict[str, list[str]]:
        """Guarded argument -> its atoms that trace to neither the user, a trusted tool, nor an approval
        given for this same tool and argument."""
        bad: dict[str, list[str]] = {}
        checks = [(a, False) for a in self.policy.forbid_tainted.get(tool, [])]
        checks += [(a, True) for a in self.policy.check_links_in.get(tool, [])]  # free text: links only
        for arg, typed_only in checks:
            if arg in args:
                # strict trust: for outward args (and links in free text), a value only a WEAK trusted tool
                # returned (e.g. a contact built from an attacker's email) may not count as traceable
                outward = typed_only or arg in self.policy.outward_args.get(tool, [])
                no_weak = self.policy.no_weak_kinds(outward)
                atoms = (self.prov.unverified_atoms(args[arg], typed_only, no_weak) if self.policy.mode == "allowlist"
                         else self.prov.tainted_atoms(args[arg], typed_only, no_weak))
                atoms = [a for a in atoms if (tool, arg, canonical(a)) not in self.approved]
                if atoms:
                    bad[arg] = atoms
        return bad

    def _remember_approval(self, tool: str, args: dict[str, Any], bad: dict[str, list[str]]) -> None:
        """Approve only the values the user saw as a whole (a recipient, a URL). An email or IBAN hidden
        INSIDE an approved URL (e.g. in its query string) is not approved."""
        for arg, atoms in bad.items():
            shown = {primary_atom(s) for s in iter_strings(args[arg])}
            self.approved |= {(tool, arg, canonical(a)) for a in atoms if a in shown}

    def check_call(self, tool: str, args: dict[str, Any]) -> Decision:
        self.n_calls += 1
        if self.policy.unknown_tools == "block" and tool not in self.policy.known_tools():
            # default-deny: a tool nobody has classified yet might send, pay or delete; don't guess
            d = Decision(False, tool, f"blocked: {tool} is not in the guard's policy, and unknown tools are "
                         "blocked. Do not retry it.")
            self.decisions.append(d)
            self.all_decisions.append(d)
            return d
        bad = self._untraceable(tool, args)
        # always_confirm tools (e.g. delete_file) have no argument we can trace: deleting file "13" looks the
        # same whether the user or an injection asked for it. So they always go to the user, or are blocked.
        always = tool in self.policy.always_confirm
        exact, key = self._call_key(tool, args), self._retry_key(tool, args)
        if (bad or always) and self._use_call_approval(tool, args):
            d = Decision(True, tool, "approved by user (approved ahead of the call)", bad, approved=True)
        elif (bad or always) and exact in self.approved_calls:
            d = Decision(True, tool, "approved by user (same call as before)", bad)
        elif bad or always:
            names = ", ".join(f"{a}={v}" for a, v in bad.items())
            if self.refused.get(key, 0) >= 1 and self.confirm_fn is not None:
                # already refused once (this call or a cosmetic variant): don't ask again, tell the model to stop
                d = Decision(False, tool, "blocked: the user already declined this exact call. Do not retry it "
                             "or look for another way to do it.", bad)
            elif self.confirm_fn is not None and self.declines >= MAX_DECLINES:
                d = Decision(False, tool, f"blocked: the user has declined {self.declines} calls in this session, "
                             "so no more requests are shown to them. Only values the user gave you or that come "
                             "from trusted sources are allowed now.", bad)
            elif self.confirm_fn is not None and (always or tool in self.policy.confirmable):
                if self.confirm_fn(tool, args, bad):
                    if self.policy.approval_scope == "value":
                        # the yes keeps covering these values (and this exact call) for the session
                        self._remember_approval(tool, args, bad)
                        self.approved_calls.add(exact)
                    # scope "call": the yes is used up by this very call; nothing is remembered
                    d = Decision(True, tool, "approved by user", bad, asked=True, approved=True)
                else:
                    self.refused[key] = self.refused.get(key, 0) + 1
                    self.declines += 1
                    d = Decision(False, tool, "blocked: the user declined this call. Do not retry it or look "
                                 "for another way to do it.", bad, asked=True)
            else:
                # Plain block. Small models retry the exact same call over and over (one workspace task hit
                # 61 blocks), which burns steps and GPU time, so after a few tries say so bluntly.
                self.blocked_times[key] = self.blocked_times.get(key, 0) + 1
                if self.blocked_times[key] > PLAIN_BLOCK_RETRIES:
                    d = Decision(False, tool, "blocked: this call was already refused. Do not retry it or look "
                                 "for another way.", bad)
                elif not bad:
                    d = Decision(False, tool, f"blocked: {tool} always needs the user's approval, and there is no "
                                 "one to approve it here. Do not retry it.", bad)
                else:
                    d = Decision(False, tool, f"blocked: argument(s) not traceable to the user or a trusted source "
                                 f"({names}). Only use values the user gave you or that come from trusted sources.", bad)
        else:
            d = Decision(True, tool)
        if d.allowed and tool not in self.policy.trusted_tools:
            # remember what the agent wrote, so a trusted tool echoing it back later can't launder it
            for value in args.values():
                self.prov.note_written(value)
        self.decisions.append(d)
        self.all_decisions.append(d)
        return d

    def stats(self) -> dict:
        blocked = [d for d in self.all_decisions if not d.allowed]
        by_tool: dict[str, int] = {}
        for d in blocked:
            by_tool[d.tool] = by_tool.get(d.tool, 0) + 1
        return {"sessions": self.n_sessions, "guarded_checks": len(self.all_decisions),
                "blocked": len(blocked), "blocked_by_tool": by_tool,
                "asked": sum(d.asked for d in self.all_decisions),
                "approved": sum(d.approved for d in self.all_decisions)}

    def reset_stats(self) -> None:
        """Zero the counters, so the clean run and the attacked run can be counted separately."""
        self.all_decisions = []
        self.n_sessions = 0
