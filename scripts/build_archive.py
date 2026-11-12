"""Build the release archive of the frozen Kaggle runs (logs only), with the commit each one ran on.

  python scripts/build_archive.py --out <folder>        # writes <folder>/tracklimits-frozen-logs/ and the .tar.gz

Reads the extracted Kaggle outputs under runs/_zNN/mcp-guard/ (git-ignored, never changed). For each run it copies
only runs/**.json (AgentDojo logs + summaries): no cell printout, no ollama.log, no repo checkout. The commit is
read from that checkout's .git/HEAD, i.e. the code that actually ran.

Redaction: every email address that is neither in AgentDojo's own data nor on a reserved example domain (the
model sometimes makes addresses up, e.g. dora@website.com) is replaced, everywhere, by the same local part at
redacted-N.invalid (one N per address, so equal values stay equal and the guard decides the same on a replay:
both are untraceable). The list goes into the archive's REDACTIONS.md. Run scripts/scan_archive.py on the result.

The tarball is reproducible: sorted members, fixed mtime / owner, gzip without a timestamp.
"""
import argparse
import gzip
import hashlib
import io
import json
import re
import shutil
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_archive import EMAIL, RESERVED, agentdojo_emails  # noqa: E402

NAME = "tracklimits-frozen-logs"
# name -> (source folder under runs/, what it is). The commit comes from the run's own checkout.
RUNS = {
    "F1": ("_z11", "slack, important_instructions, Qwen2.5-7B: none / mcp_guard / confirm_oracle / confirm_yes / "
                   "trust_full / confirm_oracle_trust_full, 21 user tasks x inj 0-4 + 21 clean, 1 h cap per defense"),
    "F2": ("_z10", "banking, tool_knowledge, Qwen2.5-7B: none + 7 guard variants, user tasks 0 2 3 4 5 6 9 11 12 13 "
                   "14 15 x inj 0-4 + 12 clean"),
    "F4": ("_z13", "slack ablations, important_instructions, Qwen2.5-7B: no_trusted / no_links, F1 settings"),
    "F5": ("_z12", "slack, important_instructions, Qwen2.5-7B: confirm_oracle / confirm_yes / confirm_oracle_trust_full "
                   "on the P2 guard (approved exact calls not asked again), F1 settings"),
    "F7r": ("_z16", "workspace, important_instructions, Qwen2.5-14B: none / mcp_guard / confirm_oracle, user tasks "
                    "4 13 15 19 20 x inj 0-9 + 5 clean"),
    "F9": ("_z19", "workspace, important_instructions, Qwen2.5-14B, --freeze-clock: none / mcp_guard / confirm_oracle, "
                   "user tasks 4 13 15 19 20 x inj 10-13 + 5 clean"),
}
README = """TrackLimits frozen logs (formerly mcp-guard)

AgentDojo v1.2.2 logs of the Kaggle runs the README's tables come from. One folder per run; inside, the layout
AgentDojo wrote: runs/<defense>/[clock-frozen/]local-<model>-<defense>/<suite>/user_task_N/<attack>/
injection_task_N.json (none/none.json = the clean run) plus summary_*.json. Defense names are the ones the runs were
recorded under (mcp_guard... = tracklimits...). MANIFEST.json gives each run's commit (git rev-parse HEAD of the
checkout that ran it), its settings and a SHA-256 for every file. REDACTIONS.md lists what was changed.

Rebuild the tables: python scripts/make_tables.py --archive <this folder or the .tar.gz>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = Path(a.out) / NAME
    if out.exists():
        shutil.rmtree(out)
    known = agentdojo_emails()

    files = {}  # archive-relative path -> text
    manifest = {"name": NAME, "agentdojo": "0.1.35 (benchmark v1.2.2)", "runs": {}}
    for run, (src, what) in RUNS.items():
        base = ROOT / "runs" / src / "mcp-guard"
        commit = (base / ".git" / "HEAD").read_text().strip()
        assert re.fullmatch(r"[0-9a-f]{40}", commit), f"{run}: HEAD is not a detached commit: {commit}"
        stamps = []
        for p in sorted((base / "runs").rglob("*.json")):
            rel = f"{run}/runs/{p.relative_to(base / 'runs').as_posix()}"
            files[rel] = p.read_text(encoding="utf-8")
            if "user_task_" in rel:
                stamps.append(json.loads(files[rel]).get("evaluation_timestamp") or "")
        manifest["runs"][run] = {"commit": commit, "what": what, "first_log": min(s for s in stamps if s),
                                 "last_log": max(stamps)}

    # Redact made-up / unknown addresses, the same replacement everywhere.
    found = sorted({e.lower() for t in files.values() for e in EMAIL.findall(t)} - known)
    to_redact = [e for e in found if not RESERVED.search(e)]
    repl = {e: f"{e.split('@')[0]}@redacted-{i}.invalid" for i, e in enumerate(to_redact, 1)}
    counts = dict.fromkeys(repl, 0)
    for rel, t in files.items():
        for e, r in repl.items():
            t, n = re.subn(re.escape(e), r, t, flags=re.I)
            counts[e] += n
        files[rel] = t

    lines = ["# Redactions", "", "Applied by scripts/build_archive.py. Each original was replaced in every file, the "
             "same way each time. The originals are not repeated here: email addresses the model made up for AgentDojo's "
             "characters, on domains that are not reserved for examples, so a real person could own them.", "",
             "| replaced by | occurrences |", "|---|---|"]
    lines += [f"| {r} | {counts[e]} |" for e, r in repl.items()]
    lines += ["", "Left out of the archive entirely: ollama.log (server log), the Kaggle cell printouts, the repository "
              "checkout (.git and source).", "", "Kept: addresses on reserved example domains (RFC 2606: no real person "
              "can own one): " + ", ".join(e for e in found if e not in repl) + "."]
    files["REDACTIONS.md"] = "\n".join(lines) + "\n"
    files["README.txt"] = README
    manifest["files"] = {rel: hashlib.sha256(t.encode("utf-8")).hexdigest() for rel, t in sorted(files.items())
                         if rel not in ("REDACTIONS.md", "README.txt")}
    files["MANIFEST.json"] = json.dumps(manifest, indent=1) + "\n"

    for rel, t in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(t.encode("utf-8"))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for rel in sorted(files):
            data = files[rel].encode("utf-8")
            info = tarfile.TarInfo(f"{NAME}/{rel}")
            info.size, info.mtime, info.mode, info.uname, info.gname = len(data), 0, 0o644, "", ""
            tar.addfile(info, io.BytesIO(data))
    tgz = Path(a.out) / f"{NAME}.tar.gz"
    with open(tgz, "wb") as f, gzip.GzipFile(fileobj=f, mode="wb", mtime=0, filename="") as gz:
        gz.write(buf.getvalue())
    print(f"{len(files)} files, {len(repl)} address(es) redacted -> {tgz} "
          f"({tgz.stat().st_size / 1e6:.1f} MB, sha256 {hashlib.sha256(tgz.read_bytes()).hexdigest()})")


if __name__ == "__main__":
    main()
