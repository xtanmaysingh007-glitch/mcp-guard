"""Scan a folder of logs for things that must not be published, before it goes into a release archive.

  python scripts/scan_archive.py <folder> [--json findings.json]

Looks in every file for:
  - API keys / tokens: Google / Gemini (AIza...), GitHub (ghp_ / gho_ / ghu_ / ghs_ / ghr_ / github_pat_), Kaggle
    (KGAT_... and "key": "<32 hex>"), OpenAI-style sk-..., "Bearer ..." headers, private key blocks;
  - local paths: C:\\Users\\..., /Users/..., /home/..., /root/..., /kaggle/...;
  - the owner's names and account names (OWNER_WORDS);
  - email addresses that are NOT in AgentDojo's own data (its suites' environments and task files are fake
    people; anything else is listed for a human to look at: model inventions or real addresses); addresses on
    reserved example domains (example.com, *.invalid, *.test) are listed too, but don't count as findings;
  - server logs (ollama.log, *.log) as whole files.
Prints every hit with its file and a short context. Exit code 1 if anything was found. It only reports: it
never changes a file.
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

PATTERNS = {
    "google api key": r"AIza[0-9A-Za-z_\-]{35}",
    "github token": r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})",
    "kaggle token": r"\bKGAT_[A-Za-z0-9]{16,}|\"key\"\s*:\s*\"[0-9a-f]{32}\"",
    "openai-style key": r"\bsk-[A-Za-z0-9_\-]{20,}",
    "bearer header": r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}",
    "private key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "env assignment": r"(?i)\b(?:GEMINI|GOOGLE|KAGGLE|GITHUB|OPENAI|HF)_?(?:API_)?(?:KEY|TOKEN)\s*[=:]\s*\S+",
    "windows user path": r"(?i)[A-Z]:\\\\?(?:Users|Documents and Settings)\\\\?[^\\\"\s]+",
    "unix home path": r"(?<![\w.])/(?:Users|home|root)/[^\s\"']+",
    "kaggle path": r"/kaggle/[^\s\"']+",
}
# The owner's names and accounts (lower case). Matched as whole words.
OWNER_WORDS = ["tanmay", "xtanmay", "xtanmaysingh007", "tan07", "toxic"]
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Domains reserved for examples (RFC 2606 / RFC 6761): no real person can have an address there.
RESERVED = re.compile(r"@(?:[a-z0-9\-]+\.)*(?:example\.(?:com|org|net)|[a-z0-9\-]+\.(?:invalid|test|example))$")


def agentdojo_emails() -> set[str]:
    """Every email address in the installed AgentDojo package (environments, injection vectors, task code)."""
    import agentdojo
    root = Path(agentdojo.__file__).parent
    found = set()
    for p in root.rglob("*"):
        if p.suffix in (".yaml", ".yml", ".py", ".json", ".txt", ".md") and p.is_file():
            found |= {e.lower() for e in EMAIL.findall(p.read_text(encoding="utf-8", errors="ignore"))}
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("--json")
    a = ap.parse_args()
    known = agentdojo_emails()
    hits = defaultdict(list)          # kind -> [(file, match, context)]
    other_emails = defaultdict(set)   # address -> files
    reserved = defaultdict(set)
    root = Path(a.folder)
    for p in sorted(x for x in root.rglob("*") if x.is_file()):
        rel = str(p.relative_to(root))
        if p.suffix == ".log" or p.name.startswith("ollama"):
            hits["server / cell log file"].append((rel, p.name, ""))
        t = p.read_text(encoding="utf-8", errors="ignore")
        for kind, pat in PATTERNS.items():
            for m in re.finditer(pat, t):
                hits[kind].append((rel, m.group(0)[:80], t[max(0, m.start() - 60):m.end() + 40].replace("\n", " ")))
        for w in OWNER_WORDS:
            for m in re.finditer(rf"(?i)(?<![a-z0-9]){w}(?![a-z0-9])", t):
                hits[f"owner word '{w}'"].append((rel, m.group(0), t[max(0, m.start() - 60):m.end() + 40].replace("\n", " ")))
        for e in EMAIL.findall(t):
            if e.lower() in known:
                continue
            (reserved if RESERVED.search(e.lower()) else other_emails)[e.lower()].add(rel)
    for kind, rows in hits.items():
        print(f"\n== {kind}: {len(rows)} hit(s) in {len({r[0] for r in rows})} file(s)")
        for rel, m, ctx in rows[:5]:
            print(f"   {rel}: {m!r}  ...{ctx}...")
    print(f"\n== emails not in AgentDojo's data: {len(other_emails)} address(es)")
    for e, files in sorted(other_emails.items()):
        print(f"   {e}  ({len(files)} file(s), e.g. {sorted(files)[0]})")
    print(f"\n== (not a finding) emails on reserved example domains: {len(reserved)} address(es)")
    for e, files in sorted(reserved.items()):
        print(f"   {e}  ({len(files)} file(s))")
    if a.json:
        Path(a.json).write_text(json.dumps({"hits": hits, "other_emails": {k: sorted(v) for k, v in other_emails.items()}},
                                           indent=1), encoding="utf-8")
    sys.exit(1 if hits or other_emails else 0)


if __name__ == "__main__":
    main()
