"""Provenance tracking: where did a value in a tool call come from?

Sources per session:
  user      - the user's own request: trusted as free text (the user wrote all of it)
  trusted tool outputs - trusted only as WHOLE VALUES (each list item / field / line), never as free
              text. An attacker who smuggles text into a trusted source (e.g. a Slack channel NAME
              containing "visit www.evil.com") cannot make the URL inside it trusted.
  untrusted - outputs of every other tool (emails, files, web pages, messages, reviews ...)

Atoms are what we compare:
  typed atoms  - emails, URLs, IBANs. Must match EXACTLY (set membership), so an attacker cannot
                 pass "b@corp.com" just because the trusted text contains "bob@corp.com".
  whole values - other short values (channel, user, hotel names). Must match on word boundaries.
Comparison is case-insensitive; IBANs ignore spaces; URLs ignore trailing punctuation.

Checks:
  unverified_atoms - atoms NOT traceable to trusted data (allowlist / default-deny). The design is
                     public on purpose: knowing it does not help an attacker, who only controls
                     untrusted data. Obfuscation/translation does not put a value into trusted data.
  tainted_atoms    - atoms seen in untrusted data but not trusted (blocklist; weaker; ablation only)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

import yaml

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"(?:https?://|www\.)[^\s\"'<>)\]]+", re.IGNORECASE)
# IBAN, optionally written in groups of 4 separated by single spaces
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
_WS = re.compile(r"\s+")
_NAME_ADDR = re.compile(r"[\w .'-]{0,60}<\s*[^<>\s]+\s*>")
MIN_WHOLE_VALUE_LEN = 3


def _clean_url(u: str) -> str:
    return u.rstrip(".,;:!?").lower()


def typed_atoms(text: str) -> set[str]:
    out = {e.lower() for e in _EMAIL.findall(text)}
    out |= {_clean_url(u) for u in _URL.findall(text)}
    out |= {i.replace(" ", "").lower() for i in _IBAN.findall(text)}
    return out


def _flat(s: str) -> str:
    return _WS.sub(" ", s.lower()).strip()


def iter_strings(value: Any) -> Iterable[str]:
    """Flatten str / list / dict / scalar argument values into strings."""
    if value is None:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from iter_strings(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from iter_strings(v)
    else:
        yield str(value)


def extract_atoms(value: Any, typed_only: bool = False) -> list[tuple[str, str]]:
    """[(kind, atom)] with kind 'typed' or 'whole'. typed_only: only emails/URLs/IBANs (for free text)."""
    atoms: list[tuple[str, str]] = []
    for s in iter_strings(value):
        s = s.strip()
        found = typed_atoms(s)
        if found:
            atoms += [("typed", a) for a in sorted(found)]
        elif not typed_only and len(s) >= MIN_WHOLE_VALUE_LEN:
            atoms.append(("whole", _flat(s)))
    return atoms


@dataclass
class _Corpus:
    typed: set[str] = field(default_factory=set)
    text: str = ""
    n: int = 0

    def add(self, s: str) -> None:
        self.typed |= typed_atoms(s)
        self.text += "\n" + _flat(s)
        self.n += 1

    def contains(self, kind: str, atom: str) -> bool:
        if kind == "typed":
            return atom in self.typed
        return re.search(r"(?<!\w)" + re.escape(atom) + r"(?!\w)", self.text) is not None


def leaf_values(text: str) -> list[str]:
    """Split a tool output into whole values: YAML list items / mapping values, else lines.
    A line like 'Hotel Names: Le Marais Boutique' also yields 'Le Marais Boutique'."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        data = text
    if not isinstance(data, (dict, list, tuple)):
        data = str(text)
    leaves: list[str] = []
    for s in iter_strings(data):
        for line in s.splitlines():
            line = line.strip()
            if not line:
                continue
            leaves.append(line)
            if ": " in line:
                leaves.append(line.split(": ", 1)[1].strip())
    return leaves


@dataclass
class _Values:
    """Exact whole values from trusted tools."""
    whole: set[str] = field(default_factory=set)
    typed: set[str] = field(default_factory=set)

    def add(self, text: str) -> None:
        for leaf in leaf_values(text):
            flat = _flat(leaf)
            self.whole.add(flat)
            found = typed_atoms(leaf)
            # Only trust a typed atom if it IS the whole value (an email field) or the value is exactly
            # "Name <atom>" (common contact format) - never free text that merely contains it.
            if len(found) == 1:
                atom = next(iter(found))
                if atom in (flat, flat.replace(" ", ""), _clean_url(flat)) or _NAME_ADDR.fullmatch(flat):
                    self.typed |= found

    def contains(self, kind: str, atom: str) -> bool:
        return atom in (self.typed if kind == "typed" else self.whole)


@dataclass
class Provenance:
    user: _Corpus = field(default_factory=_Corpus)
    tool_values: _Values = field(default_factory=_Values)
    untrusted: _Corpus = field(default_factory=_Corpus)

    def add_user(self, text: str) -> None:
        self.user.add(text)

    def add_approved(self, atoms: list[str]) -> None:
        """The user said yes to these exact values (confirm mode): from now on they count as user-given."""
        for a in atoms:
            self.user.typed.add(a)
            self.user.text += "\n" + a

    def add_trusted(self, text: str) -> None:
        """Output of a trusted tool: only its whole values become trusted."""
        self.tool_values.add(text)

    def add_untrusted(self, text: str) -> None:
        self.untrusted.add(text)

    def is_trusted(self, kind: str, atom: str) -> bool:
        return self.user.contains(kind, atom) or self.tool_values.contains(kind, atom)

    def unverified_atoms(self, value: Any, typed_only: bool = False) -> list[str]:
        return [a for k, a in extract_atoms(value, typed_only) if not self.is_trusted(k, a)]

    def tainted_atoms(self, value: Any, typed_only: bool = False) -> list[str]:
        return [a for k, a in extract_atoms(value, typed_only)
                if not self.is_trusted(k, a) and self.untrusted.contains(k, a)]
