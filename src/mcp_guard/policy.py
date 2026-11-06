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
    mode: str = "allowlist"  # allowlist: guarded args must trace to trusted data (default-deny)
                             # taint: block only values seen verbatim in untrusted data (weaker)

    def __post_init__(self):
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            trusted_tools=set(data.get("trusted_tools", [])),
            forbid_tainted={k: list(v) for k, v in (data.get("forbid_tainted") or {}).items()},
            confirmable=set(data.get("confirmable", [])),
            mode=data.get("mode", "allowlist"),
            check_links_in={k: list(v) for k, v in (data.get("check_links_in") or {}).items()},
        )

    def with_mode(self, mode: str) -> "Policy":
        return replace(self, mode=mode)

    def without_trusted_tools(self) -> "Policy":
        """Ablation: treat every tool output as untrusted."""
        return replace(self, trusted_tools=set())

    def without_link_checks(self) -> "Policy":
        """Ablation: do not scan free-text args for links/emails/IBANs."""
        return replace(self, check_links_in={})


DEFAULT_POLICY_PATH = Path(__file__).parent / "policies" / "agentdojo.yaml"
