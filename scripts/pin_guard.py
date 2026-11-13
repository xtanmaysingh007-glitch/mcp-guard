"""Pin the guard to the review-freeze tag for a benchmark run, and prove that's what runs.

  python scripts/pin_guard.py            # check only: AST comparison of HEAD's guard files with the tag
  python scripts/pin_guard.py --restore  # check, then restore the guard files from the tag and verify their hash

Used by the M5 Kaggle cells (docs/m5_design.md). M5's own code (scripts/m5_tasks.py, m5_spec.py, the flags in
run_agentdojo.py, attribution.py) is outside GUARD_FILES, so restoring never overwrites it.

GUARD_FILES: the files the guard's decisions come from. guard.py imports policy.py and provenance.py, which import
only the standard library and PyYAML; policy_for() in agentdojo_adapter.py builds the policy from
policies/agentdojo.yaml and its executor is what calls check_call / record_result, so it is pinned too.

Steps, each printed; exit code 1 (stop the run) on any failure:
1. the tag's commit, HEAD's commit;
2. AST comparison, per file, of HEAD's version with the tag's: Python with docstrings removed (ast.dump ignores
   comments, line numbers and formatting), YAML as the parsed data (comments don't parse). Any difference = the
   drift since the tag is not comments / docstrings only = fail;
3. with --restore: git checkout <tag> -- GUARD_FILES, then a SHA-256 over the files on disk compared with the same
   hash over the tag's blobs (line endings normalized, so a Windows checkout gives the same number).
"""
import argparse
import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TAG = "review-freeze"
GUARD_FILES = ["src/tracklimits/guard.py", "src/tracklimits/policy.py", "src/tracklimits/provenance.py",
               "src/tracklimits/policies/agentdojo.yaml", "src/tracklimits/agentdojo_adapter.py"]


def git(*args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=True).stdout


def at(ref: str, path: str) -> bytes:
    return git("show", f"{ref}:{path}")


def strip_docstrings(tree: ast.AST) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    return tree


def structure(path: str, data: bytes) -> str:
    """What a file means, without comments / docstrings / formatting."""
    text = data.decode("utf-8")
    if path.endswith(".py"):
        return ast.dump(strip_docstrings(ast.parse(text)))
    return json.dumps(yaml.safe_load(text), sort_keys=True)


def compare(ref_a: str, ref_b: str | None = None) -> dict[str, bool]:
    """file -> same meaning in ref_a and ref_b (None = the working tree)."""
    out = {}
    for f in GUARD_FILES:
        b = (ROOT / f).read_bytes() if ref_b is None else at(ref_b, f)
        out[f] = structure(f, at(ref_a, f)) == structure(f, b)
    return out


def files_hash(read) -> str:
    h = hashlib.sha256()
    for f in GUARD_FILES:
        h.update(f.encode() + b"\0" + read(f).replace(b"\r\n", b"\n") + b"\0")
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--restore", action="store_true")
    a = ap.parse_args()
    tag_commit = git("rev-parse", f"{TAG}^{{commit}}").decode().strip()
    head = git("rev-parse", "HEAD").decode().strip()
    tag_hash = files_hash(lambda f: at(TAG, f))
    print(f"{TAG} commit: {tag_commit}")
    print(f"M5 (HEAD) commit:      {head}")
    print(f"{TAG} guard-files hash: {tag_hash}")
    same = compare(TAG, "HEAD")
    for f, ok in same.items():
        print(f"  AST {f}: {'same as ' + TAG if ok else 'DIFFERENT'}")
    if not all(same.values()):
        sys.exit("STOP: guard code at HEAD differs from review-freeze beyond comments / docstrings")
    print("AST comparison: OK (drift since the tag, if any, is comments / docstrings only)")
    if a.restore:
        git("checkout", TAG, "--", *GUARD_FILES)
        disk_hash = files_hash(lambda f: (ROOT / f).read_bytes())
        print(f"guard-files hash on disk after restore: {disk_hash}")
        if disk_hash != tag_hash:
            sys.exit("STOP: restored guard files do not hash to the review-freeze blobs")
        print("hash check: OK (the run uses review-freeze's guard files byte for byte)")


if __name__ == "__main__":
    main()
