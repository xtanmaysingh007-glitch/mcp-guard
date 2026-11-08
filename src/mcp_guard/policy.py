"""Policy: which tools are trusted data sources, and which arguments must not be tainted."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

import yaml


MODES = ("allowlist", "taint")


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
    strict_trust: bool = False  # True: weak tools' values don't count for outward args (or links in free text)
    mode: str = "allowlist"  # allowlist: guarded args must trace to trusted data (default-deny)
                             # taint: block only values seen verbatim in untrusted data (weaker)

    def __post_init__(self):
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
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
            strict_trust=bool(data.get("strict_trust", False)),
        )

    def with_mode(self, mode: str) -> "Policy":
        return replace(self, mode=mode)

    def with_strict_trust(self) -> "Policy":
        """Experiment: weak trusted tools' values are refused for outward arguments."""
        return replace(self, strict_trust=True)

    def without_trusted_tools(self) -> "Policy":
        """Ablation: treat every tool output as untrusted."""
        return replace(self, trusted_tools=set(), weak_trusted_tools=set())

    def without_link_checks(self) -> "Policy":
        """Ablation: do not scan free-text args for links/emails/IBANs."""
        return replace(self, check_links_in={})


DEFAULT_POLICY_PATH = Path(__file__).parent / "policies" / "agentdojo.yaml"
