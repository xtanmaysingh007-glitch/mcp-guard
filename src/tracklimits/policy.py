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
SELF_NOTE_TOOLS = {"send_email": ["recipients", "body"]}


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
    # off / typed / full, see TRUST_SETTINGS. Fail-safe default (2026-11-11): typed, the project default, so a
    # policy that forgets the key doesn't silently trust weak tools for outward args. "off" must be explicit.
    strict_trust: str = "typed"
    unknown_tools: str = "allow"  # allow / block, see UNKNOWN_SETTINGS
    safe_tools: set[str] = field(default_factory=set)  # listed on purpose: read-only, nothing to guard
    approval_scope: str = "value"  # value / call, see APPROVAL_SCOPES: the default for every tool ...
    approval_scope_by_tool: dict[str, str] = field(default_factory=dict)  # ... and per-tool overrides
    approval_ttl_calls: int = 5    # call scope: a stored approval expires after this many checked calls
    # Message to self (2026-11-11): for these tools, when EVERY recipient is one of user_identities, the text args
    # must not copy self_note_copy_words+ words of untrusted text, nor carry a digit run of self_note_min_digits+
    # digits that traces to neither the user nor a trusted tool (an attacker's "note to self" with a ransom IBAN).
    # tool -> [recipient arg, text arg, ...]. 0 switches that half off. Missing keys get these (safe) defaults.
    self_note_tools: dict[str, list[str]] = field(default_factory=lambda: dict(SELF_NOTE_TOOLS))
    # tool -> arguments that are secrets (a new password): must equal a token the user quoted in the request
    secret_args: dict[str, list[str]] = field(default_factory=dict)
    self_note_copy_words: int = 6
    self_note_min_digits: int = 8
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
    def from_yaml(cls, path: str | Path, tool_args: dict[str, set[str]] | None = None) -> "Policy":
        """Load a policy file, strictly: a file that loads but guards less than it says is worse than an error
        (review R6: a scalar where a list belongs used to load as a list of letters, guarding nothing).
        Errors: an empty file, unknown or duplicate keys, wrong shapes. tool_args (tool -> its argument names),
        when given, also catches misspelled tools and arguments."""
        data = _load_strict(Path(path).read_text(encoding="utf-8"), str(path))
        if tool_args is not None:
            _check_names(data, tool_args, str(path))
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
            strict_trust=_trust_setting(data.get("strict_trust", "typed")),   # missing key: fail-safe
            unknown_tools=str(data.get("unknown_tools", "allow")),
            safe_tools=set(data.get("safe_tools") or []),
            approval_scope=str(data.get("approval_scope", "value")),
            approval_scope_by_tool={k: str(v) for k, v in (data.get("approval_scope_by_tool") or {}).items()},
            approval_ttl_calls=int(data.get("approval_ttl_calls", 5)),
            # missing or empty -> the safe defaults; an explicit 0 switches a check off
            self_note_tools=({k: list(v) for k, v in data["self_note_tools"].items()}
                             if data.get("self_note_tools") else dict(SELF_NOTE_TOOLS)),
            secret_args={k: list(v) for k, v in (data.get("secret_args") or {}).items()},
            self_note_copy_words=_count(data.get("self_note_copy_words"), 6),
            self_note_min_digits=_count(data.get("self_note_min_digits"), 8),
        )

    def with_mode(self, mode: str) -> "Policy":
        return replace(self, mode=mode)

    def known_tools(self) -> set[str]:
        """Every tool the policy says something about. Anything else is "unknown"."""
        return (self.trusted_tools | self.safe_tools | self.confirmable | self.always_confirm
                | set(self.forbid_tainted) | set(self.check_links_in) | set(self.outward_args) | set(self.secret_args))

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


# ---------------------------------------------------------------------------------------- strict loading
# The keys a policy file may have, and their shape. "unclassified" is what `tracklimits init` writes for tools
# nobody has decided about yet (blocked under unknown_tools: block); the guard ignores it.
LIST_KEYS = ("trusted_tools", "confirmable", "always_confirm", "user_identities", "weak_trusted_tools",
             "safe_tools", "unclassified")
ARG_MAP_KEYS = ("forbid_tainted", "check_links_in", "outward_args", "self_note_tools", "secret_args")  # tool -> [arg]
SCALAR_KEYS = ("strict_trust", "unknown_tools", "approval_scope", "mode")
INT_KEYS = ("approval_ttl_calls", "self_note_copy_words", "self_note_min_digits")
MAP_KEYS = ("approval_scope_by_tool",)                                                    # tool -> word
KNOWN_KEYS = set(LIST_KEYS + ARG_MAP_KEYS + SCALAR_KEYS + INT_KEYS + MAP_KEYS)


class _NoDuplicates(yaml.SafeLoader):
    """A YAML loader that refuses a key written twice (PyYAML silently keeps the last one)."""


def _mapping_no_duplicates(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise ValueError(f"duplicate key {key!r} (line {key_node.start_mark.line + 1})")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_NoDuplicates.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping_no_duplicates)


def _load_strict(text: str, where: str) -> dict:
    data = yaml.load(text, Loader=_NoDuplicates)
    if not isinstance(data, dict) or not data:
        raise ValueError(f"{where}: a policy must be a non-empty mapping of settings")
    unknown = set(data) - KNOWN_KEYS
    if unknown:
        raise ValueError(f"{where}: unknown key(s) {sorted(unknown)}; known: {sorted(KNOWN_KEYS)}")
    for key, value in data.items():
        if value is None:
            continue                                   # "key:" with nothing after it = empty / the default
        if key in LIST_KEYS and not (isinstance(value, list) and all(isinstance(v, str) for v in value)):
            raise ValueError(f"{where}: {key} must be a list of names, got {value!r}")
        if key in ARG_MAP_KEYS:
            if not isinstance(value, dict) or not all(
                    isinstance(k, str) and isinstance(v, list) and all(isinstance(a, str) for a in v)
                    for k, v in value.items()):
                raise ValueError(f"{where}: {key} must map each tool to a LIST of argument names "
                                 f"(e.g. send_money: [recipient]), got {value!r}")
        if key in MAP_KEYS and not (isinstance(value, dict) and all(isinstance(v, str) for v in value.values())):
            raise ValueError(f"{where}: {key} must map tools to a word, got {value!r}")
        if key in INT_KEYS and (isinstance(value, bool) or not isinstance(value, int)):
            raise ValueError(f"{where}: {key} must be a whole number, got {value!r}")
        if key in SCALAR_KEYS and not isinstance(value, (str, bool)):
            raise ValueError(f"{where}: {key} must be a single word, got {value!r}")
    return data


def _check_names(data: dict, tool_args: dict[str, set[str]], where: str) -> None:
    """Every tool the policy names exists, and every argument it names exists on that tool."""
    for key in LIST_KEYS + MAP_KEYS:
        if key == "user_identities":
            continue
        for tool in (data.get(key) or []):
            if tool not in tool_args:
                raise ValueError(f"{where}: {key} names unknown tool {tool!r}")
    for key in ARG_MAP_KEYS:
        for tool, args in (data.get(key) or {}).items():
            if tool not in tool_args:
                raise ValueError(f"{where}: {key} names unknown tool {tool!r}")
            missing = set(args) - set(tool_args[tool])
            if missing:
                raise ValueError(f"{where}: {key}.{tool} names argument(s) {sorted(missing)} that {tool} doesn't "
                                 f"have; it has {sorted(tool_args[tool])}")


def _count(value, default: int) -> int:
    """A non-negative whole number from YAML; missing / empty -> default (the safe one)."""
    if value is None:
        return default
    n = int(value)
    if n < 0:
        raise ValueError("self_note thresholds must be 0 (off) or more")
    return n


def _trust_setting(value) -> str:
    """YAML may say true/false (older files): true = full, false = off. An empty value (the key with nothing
    after it) is the fail-safe default, typed, like a missing key."""
    if value is True:
        return "full"
    if value is None:
        return "typed"
    if value is False:
        return "off"
    return str(value)


DEFAULT_POLICY_PATH = Path(__file__).parent / "policies" / "agentdojo.yaml"
