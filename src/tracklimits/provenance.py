"""Provenance tracking: where did a value in a tool call come from?

Sources per session:
  user      - the user's own request: trusted as free text (the user wrote all of it)
  trusted tool outputs - trusted only as WHOLE VALUES (each list item / field / line), never as free
              text. An attacker who smuggles text into a trusted source (e.g. a Slack channel NAME
              containing "visit www.evil.com") cannot make the URL inside it trusted.
  untrusted - outputs of every other tool (emails, files, web pages, messages, reviews ...)
  written   - untraceable values the AGENT put into calls to non-trusted tools. If a trusted tool later
              returns one, it is not trusted. Stops write-then-read laundering: write the attacker's IBAN
              into your own profile (update_user_info), read it back from trusted get_user_info, pay it.
Approvals (confirm mode) are not stored here: the guard keeps them per (tool, argument, value).

Atoms are what we compare:
  typed atoms  - emails, URLs, IBANs. Must match EXACTLY (set membership), so an attacker cannot
                 pass "b@corp.com" just because the trusted text contains "bob@corp.com".
  whole values - other values (channel, user, hotel names). Must match on word boundaries.
  A guarded argument is parsed WHOLE into one atom (whole_atom); free text is scanned for typed atoms.
Comparison is case-insensitive; IBANs ignore spaces; URLs ignore trailing punctuation.

Checks:
  unverified_atoms - atoms NOT traceable to trusted data (allowlist / default-deny). The design is
                     public on purpose: knowing it does not help an attacker, who only controls
                     untrusted data. Obfuscation/translation does not put a value into trusted data.
  tainted_atoms    - atoms seen in untrusted data but not trusted (blocklist; weaker; ablation only)
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Collection, Iterable
import ipaddress
from email.utils import parseaddr
from urllib.parse import unquote, urlsplit

import yaml

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"(?:https?://|www\.)[^\s\"'<>)\]]+", re.IGNORECASE)
# IBAN, optionally written in groups of 4 separated by single spaces
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
# ... and the sloppy forms: any case, dashes or several spaces between groups (needs >= 10 digits, so
# ordinary words like "ab12 test word more" don't count)
_IBAN_LOOSE = re.compile(r"\b[a-z]{2}\d{2}(?:[ \-]*[a-z0-9]{4}){2,7}(?:[ \-]*[a-z0-9]{1,4})?\b", re.IGNORECASE)
# A bare domain with no scheme and no "www." ("evil.com/x"). Only common top-level domains, so file names
# (report.pdf, notes.txt) don't count. Not inside an email ("@"), a longer name (".") or a URL path ("/").
_TLDS = ("com|net|org|io|co|info|biz|xyz|app|dev|me|us|uk|de|fr|ru|cn|in|ai|site|online|top|shop|ly|link|"
         "click|tk|ws|cc|tv|eu|ca|au|nl|ch|es|it|pl|se|jp|br")
_BARE = re.compile(r"(?<![\w@./-])((?:[a-z0-9-]+\.)+(?:" + _TLDS + r")(?![\w-])(?:/[^\s\"'<>)\]]*)?)",
                   re.IGNORECASE)
_WS = re.compile(r"\s+")
_NAME_ADDR = re.compile(r"[\w .'-]{0,60}<\s*[^<>\s]+\s*>")

# Text normalisation (only ever ADDS atoms: atoms are taken from the raw text and from the normalised text)
_ZERO_WIDTH = re.compile("[\u00ad\u200b-\u200f\u2060\ufeff]")
_DEFANG = [  # (pattern, replacement): undo common ways of writing a link so a filter misses it
    (re.compile(r"hxxp(s?)(://)", re.IGNORECASE), r"http\1\2"),
    (re.compile(r"\s*[\[({]\s*(?:dot|\.)\s*[\])}]\s*", re.IGNORECASE), "."),
    (re.compile(r"\s*[\[({]\s*(?:at|@)\s*[\])}]\s*", re.IGNORECASE), "@"),
    # spelled out: "bob at evil dot com" (only as a whole address, so "I work at corp.com" is untouched)
    (re.compile(r"\b([\w.+-]+)\s+at\s+([\w-]+(?:\s+dot\s+[\w-]+)+)\b", re.IGNORECASE),
     lambda m: m.group(1) + "@" + re.sub(r"\s+dot\s+", ".", m.group(2), flags=re.IGNORECASE)),
]
_SPLIT_LINE = re.compile(r"(?<=\S)[ \t]*\n[ \t]*(?=\S)")   # a line break in the middle of a token
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _clean_url(u: str) -> str:
    """Compare links without scheme, "www." or trailing slash/punctuation: http://www.a.com/ == a.com.
    (Path and query are kept: a trusted page does not make other pages of the site trusted.)"""
    u = u.rstrip(".,;:!?").lower()
    u = re.sub(r"^[a-z][a-z0-9+.-]*://", "", u)
    u = u[4:] if u.startswith("www.") else u
    return u.rstrip("/")


# ---------------------------------------------------------------------------------- whole-value parsing
# A GUARDED argument (a recipient, a URL, a payee) must be exactly one value, parsed whole: what the guard
# checks is what the tool will use. (Before 2026-11-12 the guard checked whatever atoms its regexes found
# inside the string: "https://example.com'@evil.example/x" yielded "example.com", which the user had named,
# while the tool went to evil.example. Review finding R3. Values under 3 characters were not checked at all: R1.)
_ADDR = re.compile(r"[a-z0-9.!#$%&*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+", re.IGNORECASE)   # no quotes
_NAME_ADDR_FORM = re.compile(r"[^<>@\"]*<\s*([^<>\s]+)\s*>\s*")
_SCHEMEISH = re.compile(r"[a-z][a-z0-9+.-]*:/", re.IGNORECASE)
_HOST_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)", re.IGNORECASE)
_IBAN_WHOLE = re.compile(r"[a-z]{2}\d{2}[a-z0-9]{8,30}", re.IGNORECASE)
_URL_FORBIDDEN = set(" \t\r\n\"'<>\\`{}|^")


def _valid_host(host: str | None) -> bool:
    """A DNS name (two or more labels, the last one not all digits) or an IP address."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    return (len(labels) >= 2 and all(_HOST_LABEL.fullmatch(lab) for lab in labels)
            and not labels[-1].isdigit())


def _whole_url(s: str) -> str | None:
    """s parsed whole as a URL (urllib.parse), or None. No userinfo (user@host), no spaces or quotes, a real
    host. The result has the same form as the URL atoms found in text (_clean_url), so they compare."""
    if any(c in _URL_FORBIDDEN for c in s):
        return None
    try:
        parts = urlsplit(s if "://" in s else "http://" + s)
        host = parts.hostname
    except ValueError:
        return None
    if not parts.netloc or "@" in parts.netloc or not _valid_host(host):
        return None
    return _clean_url(s)


def _whole_email(s: str) -> str | None:
    """s parsed whole as one email address ("bob@x.com" or "Bob <bob@x.com>"), lower-cased, or None.
    A quoted local part ('"bob@corp.com"@evil.com'), a second address or extra text is None."""
    name, addr = parseaddr(s)
    if not addr:
        return None
    form = _NAME_ADDR_FORM.fullmatch(s)
    if s.strip() != addr and not (form and form.group(1) == addr):
        return None
    if not _ADDR.fullmatch(addr) or not _valid_host(addr.rsplit("@", 1)[1]):
        return None
    return addr.lower()


def whole_atom(s: str) -> tuple[str, str] | None:
    """One guarded value, parsed whole: ("typed", email / URL / IBAN) or ("whole", plain value), or None when
    it does not parse as the kind it looks like (then it can't be traced, and the guard refuses it)."""
    s = s.strip()
    if not s:
        return None
    if _SCHEMEISH.match(s) or s.lower().startswith("www."):
        url = _whole_url(s)
        return ("typed", url) if url else None
    if "@" in s:
        email = _whole_email(s)
        return ("typed", email) if email else None
    compact = re.sub(r"[ \-]", "", s)
    if _IBAN_WHOLE.fullmatch(compact) and re.fullmatch(r"[A-Za-z0-9 \-]+", s) and sum(c.isdigit() for c in compact) >= 10:
        return ("typed", compact.lower())
    head = re.split(r"[/?#]", s, maxsplit=1)[0]
    if not any(c.isspace() for c in s) and "." in head:
        try:
            looks_like_host = _valid_host(urlsplit("http://" + head).hostname)
        except ValueError:
            looks_like_host = False
        if looks_like_host:                       # "evil.cloud", "203.0.113.7/login": a URL, not a name
            url = _whole_url(s)
            return ("typed", url) if url else None
    if typed_atoms(s):
        # a "name" with a link, email or IBAN inside it ("[www.evil.com](https://www.evil.com)") is not one
        # value: refuse it rather than trust it as a plain name (adaptive case B2a)
        return None
    return ("whole", _flat(s))


def _tokens_as_values(text: str) -> set[str]:
    """Typed values written as one whitespace token in free text ("evil.cloud", "203.0.113.7/x"), parsed with
    the same whole-value parser, so a value the user typed matches the same value in an argument."""
    out = set()
    for tok in text.split():
        tok = tok.strip(".,;:!?()[]{}<>\"'")
        if tok:
            r = whole_atom(tok)
            if r and r[0] == "typed":
                out.add(r[1])
    return out


def _atoms_in(text: str) -> set[str]:
    out = {e.lower() for e in _EMAIL.findall(text)}
    out |= {_clean_url(u) for u in _URL.findall(text)}
    out |= {_clean_url(u) for u in _BARE.findall(text)}
    out |= {i.replace(" ", "").lower() for i in _IBAN.findall(text)}
    for m in _IBAN_LOOSE.finditer(text):
        iban = re.sub(r"[ \-]", "", m.group()).lower()
        if sum(c.isdigit() for c in iban) >= 10:
            out.add(iban)
    return out


def normalize(text: str) -> str:
    """Zero-width characters removed, Unicode NFKC (full-width letters -> ASCII), defanged links
    (hxxp, [.], [at], "bob at evil dot com") put back, percent-encoding decoded."""
    t = unicodedata.normalize("NFKC", _ZERO_WIDTH.sub("", text))
    for pattern, repl in _DEFANG:
        t = pattern.sub(repl, t)
    return unquote(t)


def _base64_texts(text: str) -> list[str]:
    """Readable text hidden in base64 tokens (a URL to "decode and open")."""
    out = []
    for tok in _B64.findall(text):
        try:
            decoded = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            out.append(decoded)
    return out


def typed_atoms(text: str) -> set[str]:
    """Emails, links and IBANs in a text, including disguised ones (see normalize). The design rule: a
    disguise can only ADD atoms that must be traceable, never hide or replace the raw ones."""
    norm = normalize(text)
    out = _atoms_in(text) | _atoms_in(norm)
    # A link broken over two lines ("evil." / "com/login"). Joining every line break would also glue a
    # link at the end of a line to the next word, so only atoms that are new (don't contain one found
    # without joining) count.
    joined = _SPLIT_LINE.sub("", norm)
    if joined != norm:
        out |= {a for a in _atoms_in(joined) if not any(b in a for b in out)}
    for hidden in _base64_texts(norm):
        out |= _atoms_in(normalize(hidden))
    return out


_WORD = re.compile(r"[a-z0-9$']+")


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
    """[(kind, atom)] for an argument value.
    Guarded argument (typed_only False): one atom per string, parsed WHOLE (whole_atom): "typed" (email / URL /
    IBAN) or "whole" (plain value). An empty string or one that doesn't parse is ("bad", text): never trusted.
    Free text (typed_only True, check_links_in): every email / URL / IBAN found inside it."""
    atoms: list[tuple[str, str]] = []
    for s in iter_strings(value):
        if typed_only:
            atoms += [("typed", a) for a in sorted(typed_atoms(s.strip()))]
            continue
        atom = whole_atom(s)
        atoms.append(atom if atom else ("bad", _flat(s) or "<empty>"))
    return atoms


_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://")


def canonical(atom: str) -> str:
    """One form for values that mean the same thing, used to match approvals and declines: a URL loses its
    scheme, "www.", query string, fragment and trailing slash, so "HTTPS://WWW.EVIL.COM/login/?x=1" and
    "evil.com/login" are the same; emails and IBANs are lower-cased; anything else is lower-cased with
    single spaces. (Not used for trust: a trusted URL does not make other paths or queries trusted.)"""
    a = _flat(atom)
    if "@" in a and "/" not in a:
        return a.replace(" ", "")                      # email
    if _SCHEME.match(a) or a.startswith("www.") or "/" in a:
        a = _SCHEME.sub("", a)
        a = a[4:] if a.startswith("www.") else a
        a = re.split(r"[?#]", a, maxsplit=1)[0]
        return a.rstrip("/")
    return a


def canonical_value(value: Any) -> Any:
    """canonical() applied to every string inside an argument value (lists and dicts kept)."""
    if isinstance(value, str):
        return canonical(primary_atom(value) or value)
    if isinstance(value, dict):
        return {k: canonical_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [canonical_value(v) for v in value]
    return value


def call_canonical(value: Any) -> Any:
    """Every string lower-cased with single spaces, lists and dicts kept. Used for call-scoped approval keys.
    Unlike canonical_value, URLs keep their query string: "x.com/a?to=evil@attacker.com" is a different call
    from "x.com/a", so an approval for one must not cover the other."""
    if isinstance(value, str):
        return _flat(value)
    if isinstance(value, dict):
        return {k: call_canonical(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [call_canonical(v) for v in value]
    return value


def primary_atom(s: str) -> str | None:
    """The atom that IS this whole string (a recipient, a URL), or None if it doesn't parse whole. For a URL
    whose query string holds an email, the URL is the primary atom and the email is only inside it."""
    atom = whole_atom(s)
    return atom[1] if atom else None


@dataclass
class _Corpus:
    typed: set[str] = field(default_factory=set)
    text: str = ""
    n: int = 0

    def add(self, s: str) -> None:
        self.typed |= typed_atoms(s) | _tokens_as_values(s)
        self.text += "\n" + _flat(s)
        self.n += 1

    def contains(self, kind: str, atom: str) -> bool:
        if kind == "typed":
            return atom in self.typed
        if kind != "whole":
            return False                      # "bad" (unparseable) values are never found anywhere
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

    def add(self, text: str, distrust: set[tuple[str, str]] = frozenset()) -> None:
        """distrust: (kind, atom) pairs the agent itself wrote from untraceable data. A leaf holding one
        of them is skipped (not trusted): the attacker could have put it there through the agent."""
        for leaf in leaf_values(text):
            flat = _flat(leaf)
            found = typed_atoms(leaf)
            parsed = whole_atom(leaf)
            if (("whole", flat) in distrust or any(("typed", a) in distrust for a in found)
                    or (parsed and parsed in distrust)):
                continue
            self.whole.add(flat)
            if parsed and parsed[0] == "typed":   # the leaf IS one email / URL / IBAN (same parser as arguments)
                self.typed.add(parsed[1])
            # Only trust a typed atom if it IS the whole value (an email field) or the value is exactly
            # "Name <atom>" (common contact format) - never free text that merely contains it.
            if len(found) == 1:
                atom = next(iter(found))
                if atom in (flat, re.sub(r"[ -]", "", flat), _clean_url(flat)) or _NAME_ADDR.fullmatch(flat):
                    self.typed |= found

    def contains(self, kind: str, atom: str) -> bool:
        if kind == "bad":
            return False                      # an unparseable value is never trusted
        return atom in (self.typed if kind == "typed" else self.whole)


@dataclass
class Provenance:
    user: _Corpus = field(default_factory=_Corpus)
    tool_values: _Values = field(default_factory=_Values)   # strong trusted tools
    weak_values: _Values = field(default_factory=_Values)   # weak trusted tools (data an attacker can write)
    untrusted: _Corpus = field(default_factory=_Corpus)
    written: set[tuple[str, str]] = field(default_factory=set)  # (kind, atom) the agent wrote, untraceable

    def add_user(self, text: str) -> None:
        self.user.add(text)

    def add_trusted(self, text: str, weak: bool = False, also_distrust: set[tuple[str, str]] = frozenset()) -> None:
        """Output of a trusted tool: only its whole values become trusted (minus what the agent wrote, and minus
        also_distrust: the call's own untraceable arguments, which the tool may simply have echoed back).
        weak=True: a tool whose data an attacker can write (contacts built from emails, channel names);
        its values are kept apart so strict mode can refuse them for outward arguments."""
        (self.weak_values if weak else self.tool_values).add(text, self.written | set(also_distrust))

    def own_untraceable(self, value: Any) -> set[tuple[str, str]]:
        """The untraceable atoms of an argument value, also line by line and after "key: " (an echo may split
        the value differently than it was written: "x\nMallory\ny" comes back as the line "Mallory")."""
        pieces = []
        for s in iter_strings(value):
            for line in s.splitlines() or [s]:
                pieces.append(line)
                if ": " in line:
                    pieces.append(line.split(": ", 1)[1])
        out = set(self.unverified_pairs(value))
        for piece in pieces:
            if piece.strip():
                out |= set(self.unverified_pairs(piece))
        return out

    def note_written(self, value: Any) -> None:
        """The agent is calling a non-trusted tool with this argument value: remember its untraceable
        atoms, so a trusted tool that later echoes them back does not make them trusted."""
        self.written |= self.own_untraceable(value)

    def add_untrusted(self, text: str) -> None:
        self.untrusted.add(text)

    def is_trusted(self, kind: str, atom: str, no_weak: Collection[str] = ()) -> bool:
        """no_weak: atom kinds ("typed", "whole") for which a value only a weak trusted tool returned doesn't
        count (strict_trust, outward argument)."""
        return (self.user.contains(kind, atom) or self.tool_values.contains(kind, atom)
                or (kind not in no_weak and self.weak_values.contains(kind, atom)))

    def source_of(self, kind: str, atom: str) -> str:
        """Where a value came from, for audit logs (read-only, decides nothing): the first that applies of
        "user request", "trusted tool", "weak trusted tool", "untrusted tool output", "nowhere"."""
        if self.user.contains(kind, atom):
            return "user request"
        if self.tool_values.contains(kind, atom):
            return "trusted tool"
        if self.weak_values.contains(kind, atom):
            return "weak trusted tool"
        if self.untrusted.contains(kind, atom):
            return "untrusted tool output"
        return "unparseable" if kind == "bad" else "nowhere"

    def copied_untrusted_run(self, text: str, n: int) -> str | None:
        """The first run of n words in `text` that also appears in untrusted tool output but not in the user's
        request, or None. Words: lower-case letters, digits, $ and '. (Message-to-self check.)"""
        words = _WORD.findall(text.lower())
        if n <= 0 or len(words) < n:
            return None
        def runs(t: str) -> set[str]:
            w = _WORD.findall(t)
            return {" ".join(w[k:k + n]) for k in range(len(w) - n + 1)}
        untrusted, user = runs(self.untrusted.text), runs(self.user.text)
        for k in range(len(words) - n + 1):
            run = " ".join(words[k:k + n])
            if run in untrusted and run not in user:
                return run
        return None

    def untraceable_numbers(self, text: str, min_digits: int) -> list[str]:
        """Digit runs of min_digits+ digits in `text` found neither in the user's request nor in a value a trusted
        tool returned (strong or weak). (Message-to-self check.)"""
        if min_digits <= 0:
            return []
        pattern = re.compile(r"(?<!\d)\d{%d,}(?!\d)" % min_digits)
        trusted = list(self.tool_values.whole) + list(self.weak_values.whole)
        def seen(num: str, t: str) -> bool:
            return re.search(r"(?<!\d)" + num + r"(?!\d)", t) is not None
        return [num for num in dict.fromkeys(pattern.findall(text))
                if not seen(num, self.user.text) and not any(seen(num, v) for v in trusted)]

    def unverified_pairs(self, value: Any, typed_only: bool = False,
                         no_weak: Collection[str] = ()) -> list[tuple[str, str]]:
        return [(k, a) for k, a in extract_atoms(value, typed_only) if not self.is_trusted(k, a, no_weak)]

    def unverified_atoms(self, value: Any, typed_only: bool = False, no_weak: Collection[str] = ()) -> list[str]:
        return [a for _, a in self.unverified_pairs(value, typed_only, no_weak)]

    def tainted_atoms(self, value: Any, typed_only: bool = False, no_weak: Collection[str] = ()) -> list[str]:
        """Taint mode (weaker, comparison only): values seen in untrusted data and not trusted. A value that
        doesn't parse whole is always reported (it can't be compared at all)."""
        return [a for k, a in extract_atoms(value, typed_only)
                if not self.is_trusted(k, a, no_weak) and (k == "bad" or self.untrusted.contains(k, a))]
