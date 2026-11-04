"""Policy: which tools are trusted data sources, and which arguments must not be tainted."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


MODES = ("allowlist", "taint")


@dataclass
class Policy:
    trusted_tools: set[str] = field(default_factory=set)
    forbid_tainted: dict[str, list[str]] = field(default_factory=dict)  # tool -> guarded arg names
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
            mode=data.get("mode", "allowlist"),
        )

    def with_mode(self, mode: str) -> "Policy":
        return Policy(set(self.trusted_tools), dict(self.forbid_tainted), mode)

    def without_trusted_tools(self) -> "Policy":
        """Ablation: treat every tool output as untrusted."""
        return Policy(set(), dict(self.forbid_tainted), self.mode)


DEFAULT_POLICY_PATH = Path(__file__).parent / "policies" / "agentdojo.yaml"
