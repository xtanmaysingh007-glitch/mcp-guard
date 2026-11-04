"""Provenance tracking: where did a value in a tool call come from?

Two corpora per session:
  trusted   - the user's own request, plus outputs of tools the policy declares trusted
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

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"(?:https?://|www\.)[^\s\"'<>)\]]+", re.IGNORECASE)
# IBAN, optionally written in groups of 4 separated by single spaces
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
_WS = re.compile(r"\s+")
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


def extract_atoms(value: Any) -> list[tuple[str, str]]:
    """[(kind, atom)] with kind 'typed' or 'whole'."""
    atoms: list[tuple[str, str]] = []
    for s in iter_strings(value):
        s = s.strip()
        found = typed_atoms(s)
        if found:
            atoms += [("typed", a) for a in sorted(found)]
        elif len(s) >= MIN_WHOLE_VALUE_LEN:
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


@dataclass
class Provenance:
    trusted: _Corpus = field(default_factory=_Corpus)
    untrusted: _Corpus = field(default_factory=_Corpus)

    def add_trusted(self, text: str) -> None:
        self.trusted.add(text)

    def add_untrusted(self, text: str) -> None:
        self.untrusted.add(text)

    def unverified_atoms(self, value: Any) -> list[str]:
        return [a for k, a in extract_atoms(value) if not self.trusted.contains(k, a)]

    def tainted_atoms(self, value: Any) -> list[str]:
        return [a for k, a in extract_atoms(value)
                if not self.trusted.contains(k, a) and self.untrusted.contains(k, a)]
