"""Policy: which tools are trusted data sources, and which arguments must not be tainted."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

import yaml


MODES = ("allowlist", "taint")
# strict_trust settings: how far to trust WEAK trusted tools (data an attacker can write) for outward args
#   off   - like any trusted tool
#   typed - not for emails / URLs / IBANs (an attacker's contact or link); plain names (channels, users) pass
#   full  - not at all: every weak-only value in an outward arg is untraceable
TRUST_SETTINGS = ("off", "typed", "full")
# unknown_tools: what to do with a tool the policy doesn't mention at all
#   allow - let it run (AgentDojo policy: keeps every earlier result comparable)
#   block - default-deny (the right default for a proxy: a new tool needs a decision before it can run)
UNKNOWN_SETTINGS = ("allow", "block")
# approval_scope: what a "yes" in confirm mode covers
#   value - the approved value(s), for that tool and argument, for the rest of the session (other args free)
#   call  - only that exact call (tool + every argument), once; a changed body or recipient asks again
APPROVAL_SCOPES = ("value", "call")


@dataclass
class Policy:
    trusted_tools: set[str] = field(default_factory=set)
    forbid_tainted: dict[str, list[str]] = field(default_factory=dict)  # tool -> guarded arg names
    check_links_in: dict[str, list[str]] = field(default_factory=dict)  # tool -> free-text args: links only
    confirmable: set[str] = field(default_factory=set)  # tools where a refused call may be shown to the user instead
    always_confirm: set[str] = field(default_factory=set)  # tools that need the user's OK even with clean args
    user_identities: list[str] = field(default_factory=list)  # the user's own addresses etc.: count as user-given
    weak_trusted_tools: set[str] = field(default_factory=set)  # trusted tools whose data an attacker can write
    outward_args: dict[str, list[str]] = field(default_factory=dict)  # tool -> args that send/pay/invite/visit
    strict_trust: str = "off"  # off / typed / full, see TRUST_SETTINGS
    unknown_tools: str = "allow"  # allow / block, see UNKNOWN_SETTINGS
    safe_tools: set[str] = field(default_factory=set)  # listed on purpose: read-only, nothing to guard
    approval_scope: str = "value"  # value / call, see APPROVAL_SCOPES: the default for every tool ...
    approval_scope_by_tool: dict[str, str] = field(default_factory=dict)  # ... and per-tool overrides
    approval_ttl_calls: int = 5    # call scope: a stored approval expires after this many checked calls
    mode: str = "allowlist"  # allowlist: guarded args must trace to trusted data (default-deny)
                             # taint: block only values seen verbatim in untrusted data (weaker)

    def __post_init__(self):
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        bad_scopes = {s for s in [self.approval_scope, *self.approval_scope_by_tool.values()] if s not in APPROVAL_SCOPES}
        if bad_scopes:
            raise ValueError(f"approval_scope must be one of {APPROVAL_SCOPES}")
        if self.unknown_tools not in UNKNOWN_SETTINGS:
            raise ValueError(f"unknown_tools must be one of {UNKNOWN_SETTINGS}")
        if self.strict_trust not in TRUST_SETTINGS:
            raise ValueError(f"strict_trust must be one of {TRUST_SETTINGS}")
        if not self.weak_trusted_tools <= self.trusted_tools:
            raise ValueError(f"weak_trusted_tools must be trusted tools: {self.weak_trusted_tools - self.trusted_tools}")

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            trusted_tools=set(data.get("trusted_tools", [])),
            forbid_tainted={k: list(v) for k, v in (data.get("forbid_tainted") or {}).items()},
            confirmable=set(data.get("confirmable", [])),
            always_confirm=set(data.get("always_confirm") or []),
            mode=data.get("mode", "allowlist"),
            check_links_in={k: list(v) for k, v in (data.get("check_links_in") or {}).items()},
            user_identities=[str(v) for v in (data.get("user_identities") or [])],
            weak_trusted_tools=set(data.get("weak_trusted_tools") or []),
            outward_args={k: list(v) for k, v in (data.get("outward_args") or {}).items()},
            strict_trust=_trust_setting(data.get("strict_trust", "off")),
            unknown_tools=str(data.get("unknown_tools", "allow")),
            safe_tools=set(data.get("safe_tools") or []),
            approval_scope=str(data.get("approval_scope", "value")),
            approval_scope_by_tool={k: str(v) for k, v in (data.get("approval_scope_by_tool") or {}).items()},
            approval_ttl_calls=int(data.get("approval_ttl_calls", 5)),
        )

    def with_mode(self, mode: str) -> "Policy":
        return replace(self, mode=mode)

    def known_tools(self) -> set[str]:
        """Every tool the policy says something about. Anything else is "unknown"."""
        return (self.trusted_tools | self.safe_tools | self.confirmable | self.always_confirm
                | set(self.forbid_tainted) | set(self.check_links_in) | set(self.outward_args))

    def scope_for(self, tool: str) -> str:
        """approval_scope for this tool: its override, else the default."""
        return self.approval_scope_by_tool.get(tool, self.approval_scope)

    def with_approval_scope(self, scope: str) -> "Policy":
        """The same scope for every tool (overrides dropped)."""
        return replace(self, approval_scope=scope, approval_scope_by_tool={})

    def with_unknown_tools(self, setting: str) -> "Policy":
        return replace(self, unknown_tools=setting)

    def with_strict_trust(self, setting: str = "full") -> "Policy":
        return replace(self, strict_trust=setting)

    def no_weak_kinds(self, outward: bool) -> frozenset[str]:
        """Atom kinds ("typed" = email/URL/IBAN, "whole" = plain value) for which a value that only a weak
        trusted tool returned does NOT count as traceable. Only outward arguments are affected."""
        if not outward or self.strict_trust == "off":
            return frozenset()
        return frozenset({"typed"}) if self.strict_trust == "typed" else frozenset({"typed", "whole"})

    def without_trusted_tools(self) -> "Policy":
        """Ablation: treat every tool output as untrusted."""
        return replace(self, trusted_tools=set(), weak_trusted_tools=set())

    def without_link_checks(self) -> "Policy":
        """Ablation: do not scan free-text args for links/emails/IBANs."""
        return replace(self, check_links_in={})


def _trust_setting(value) -> str:
    """YAML may say true/false (older files): true = full, false = off."""
    if value is True:
        return "full"
    if value is False or value is None:
        return "off"
    return str(value)


DEFAULT_POLICY_PATH = Path(__file__).parent / "policies" / "agentdojo.yaml"
