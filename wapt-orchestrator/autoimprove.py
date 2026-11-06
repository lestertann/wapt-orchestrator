#!/usr/bin/env python3
"""Self-improvement loop for the WAPT orchestrator.

This is the "agent that keeps improving the tool without you prompting Claude
each time." It is BOUNDED and SAFE: a change is kept only if the full test suite
still passes AND the benchmark score did not regress — otherwise it is reverted.

Each iteration:
  1. run the benchmark + tests, read the current gaps/score
  2. if there are no gaps and tests pass -> stop (nothing to do)
  3. pick the top gap, send it + the relevant source to Claude, ask for a patch
  4. back up wapt/, apply the patch
  5. re-run tests + benchmark
  6. keep it only if tests pass and the score improved; else revert
  7. log everything to improve_log.md, then repeat

Usage:
  export ANTHROPIC_API_KEY=sk-ant-...            # required
  export WAPT_IMPROVE_MODEL=claude-sonnet-4-5    # optional; set to a model you have
  python3 autoimprove.py --iterations 5

Honest limits: it spends API tokens, it only improves what bench.py measures
(so improving the benchmark is how you make the loop smarter), and LLM patches
can be wrong — which is exactly why nothing is kept unless the tests pass.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(ROOT, "wapt")
BACKUP = os.path.join(ROOT, ".autoimprove_backup")
LOG = os.path.join(ROOT, "improve_log.md")
TESTS = ["selftest.py", "livetest.py", "improvetest.py", "v4test.py", "v5test.py"]

# which source files to show Claude for each kind of gap
GAP_FILES = {
    "DETECTION": ["wapt/detectors.py", "wapt/triage.py"],
    "CONFIRM": ["wapt/confirm.py"],
}


def log(msg: str) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def run(cmd: list[str], timeout=300) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def tests_pass() -> bool:
    for t in TESTS:
        code, _ = run([sys.executable, t])
        if code != 0:
            return False
    return True


def benchmark() -> dict:
    run([sys.executable, "bench.py"])
    try:
        with open(os.path.join(ROOT, "bench_results.json")) as fh:
            return json.load(fh)
    except Exception:
        return {"gaps": ["(benchmark did not produce results)"], "detection_rate": "0/0",
                "confirm_rate": "0/0", "false_positives": 99}


def _score(b: dict) -> tuple:
    def frac(s):
        try:
            a, c = s.split("/"); return int(a) / max(int(c), 1)
        except Exception:
            return 0.0
    # higher is better: fewer gaps, more detect, more confirm, fewer FPs
    return (-len(b.get("gaps", [])), frac(b.get("detection_rate", "0/0")),
            frac(b.get("confirm_rate", "0/0")), -b.get("false_positives", 0))


def backup():
    if os.path.exists(BACKUP):
        shutil.rmtree(BACKUP)
    shutil.copytree(PKG, BACKUP)


def restore():
    if os.path.exists(BACKUP):
        shutil.rmtree(PKG)
        shutil.copytree(BACKUP, PKG)


# --------------------------------------------------------------------------- #
# the model call — returns a list of {file, old, new} edits
# --------------------------------------------------------------------------- #
def propose_patch(gap: str, files: dict[str, str], model: str) -> dict:
    import requests
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise SystemExit("ANTHROPIC_API_KEY is not set. export it and retry.")
    srcs = "\n\n".join(f"=== {path} ===\n{content}" for path, content in files.items())
    sys_prompt = (
        "You improve a defensive web-app-pentest helper tool used for authorized "
        "BSCP lab practice. You are given ONE failing benchmark gap and the relevant "
        "source files. Propose the MINIMAL change to close that gap without breaking "
        "anything else. Respond with ONLY a JSON object, no prose:\n"
        '{"rationale":"one line","edits":[{"file":"wapt/x.py","old":"<exact unique snippet>",'
        '"new":"<replacement>"}]}\n'
        "Each 'old' MUST be copied byte-for-byte from the file and be unique. "
        "Keep edits small and targeted.")
    user = f"FAILING GAP:\n{gap}\n\nSOURCE FILES:\n{srcs}"
    body = {
        "model": model, "max_tokens": 2000,
        "system": sys_prompt,
        "messages": [{"role": "user", "content": user}],
    }
    r = requests.post("https://api.anthropic.com/v1/messages", json=body, timeout=120,
                      headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                               "content-type": "application/json"})
    if r.status_code != 200:
        raise RuntimeError(f"API {r.status_code}: {r.text[:300]}")
    text = "".join(blk.get("text", "") for blk in r.json().get("content", []))
    # pull the JSON object out of the reply
    s, e = text.find("{"), text.rfind("}")
    return json.loads(text[s:e + 1])


def apply_edits(patch: dict) -> bool:
    for ed in patch.get("edits", []):
        path = os.path.join(ROOT, ed["file"])
        if not os.path.abspath(path).startswith(PKG):
            log(f"  refused edit outside wapt/: {ed['file']}")
            return False
        src = open(path, encoding="utf-8").read()
        if src.count(ed["old"]) != 1:
            log(f"  'old' not unique/found in {ed['file']} — skipping patch")
            return False
        open(path, "w", encoding="utf-8").write(src.replace(ed["old"], ed["new"]))
    return True


# --------------------------------------------------------------------------- #
def iterate(model: str, propose=propose_patch) -> str:
    """One improvement attempt. Returns 'done' | 'kept' | 'reverted' | 'stuck'."""
    before = benchmark()
    if not before.get("gaps"):
        return "done"
    if not tests_pass():
        log("baseline tests are RED — fix tests before auto-improving. stopping.")
        return "stuck"

    gap = before["gaps"][0]
    kind = gap.split(":", 1)[0].strip()
    wanted = GAP_FILES.get(kind, ["wapt/confirm.py", "wapt/detectors.py"])
    files = {p: open(os.path.join(ROOT, p), encoding="utf-8").read() for p in wanted}

    log(f"attempting gap: {gap}")
    try:
        patch = propose(gap, files, model)
    except Exception as e:
        log(f"  proposal failed: {e}")
        return "stuck"
    log(f"  rationale: {patch.get('rationale','(none)')}")

    backup()
    if not apply_edits(patch):
        restore(); return "reverted"

    if not tests_pass():
        log("  tests FAILED after patch -> reverting"); restore(); return "reverted"
    after = benchmark()
    if _score(after) > _score(before):
        log(f"  KEPT — gaps {len(before['gaps'])}->{len(after.get('gaps',[]))}, "
            f"detect {after.get('detection_rate')} confirm {after.get('confirm_rate')}")
        return "kept"
    log("  no score improvement -> reverting"); restore(); return "reverted"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Bounded self-improvement loop.")
    ap.add_argument("--iterations", type=int, default=3)
    ap.add_argument("--model", default=os.environ.get("WAPT_IMPROVE_MODEL", "claude-sonnet-4-5"))
    args = ap.parse_args(argv)

    log(f"=== auto-improve run: {args.iterations} iteration(s), model={args.model} ===")
    kept = 0
    for i in range(1, args.iterations + 1):
        log(f"--- iteration {i}/{args.iterations} ---")
        outcome = iterate(args.model)
        if outcome == "done":
            log("no gaps left — nothing to improve. (add scenarios to bench.py to go further)")
            break
        if outcome == "stuck":
            break
        kept += (outcome == "kept")
    b = benchmark()
    log(f"=== finished: {kept} improvement(s) kept. "
        f"detection {b.get('detection_rate')} confirm {b.get('confirm_rate')} "
        f"FPs {b.get('false_positives')} gaps {len(b.get('gaps',[]))} ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
