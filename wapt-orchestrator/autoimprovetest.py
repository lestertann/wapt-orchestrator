#!/usr/bin/env python3
"""Tests the self-improvement loop's SAFETY machinery without any API key:
backup/restore, apply_edits guards, and the keep-vs-revert decision (stubbed LLM).
"""
import os, autoimprove as AI

ok = True
def check(n, c):
    global ok; ok = ok and c
    print(("  PASS " if c else "  FAIL ") + n)

CONFIRM = "wapt/confirm.py"
orig = open(os.path.join(AI.ROOT, CONFIRM), encoding="utf-8").read()
MARK = '"""Active confirmation'   # unique docstring start

print("\n--- apply_edits + backup/restore ---")
AI.backup()
good = {"edits": [{"file": CONFIRM, "old": MARK, "new": '"""AUTOTEST Active confirmation'}]}
check("valid edit applies", AI.apply_edits(good) and "AUTOTEST" in open(os.path.join(AI.ROOT, CONFIRM)).read())
AI.restore()
check("restore reverts it", "AUTOTEST" not in open(os.path.join(AI.ROOT, CONFIRM)).read())
check("edit outside wapt/ is refused",
      AI.apply_edits({"edits": [{"file": "run.py", "old": "import sys", "new": "x"}]}) is False)
check("non-unique 'old' is refused",
      AI.apply_edits({"edits": [{"file": CONFIRM, "old": "return", "new": "return"}]}) is False)

print("\n--- iterate() KEEP path (patch improves score, tests pass) ---")
seq = [{"gaps": ["CONFIRM: fake"], "detection_rate": "4/4", "confirm_rate": "4/5", "false_positives": 0},
       {"gaps": [],               "detection_rate": "4/4", "confirm_rate": "5/5", "false_positives": 0}]
it = iter(seq)
AI.benchmark = lambda: next(it)
AI.tests_pass = lambda: True
stub = lambda gap, files, model: {"rationale": "t", "edits": [{"file": CONFIRM, "old": MARK, "new": '"""KEPTMARK Active confirmation'}]}
out = AI.iterate("m", propose=stub)
check("outcome is 'kept'", out == "kept")
check("kept edit remains in file", "KEPTMARK" in open(os.path.join(AI.ROOT, CONFIRM)).read())
open(os.path.join(AI.ROOT, CONFIRM), "w").write(orig)   # cleanup

print("\n--- iterate() REVERT path (tests fail after patch) ---")
AI.benchmark = lambda: {"gaps": ["CONFIRM: fake"], "detection_rate": "4/4", "confirm_rate": "4/5", "false_positives": 0}
tp = iter([True, False])   # baseline passes, post-patch fails
AI.tests_pass = lambda: next(tp)
out = AI.iterate("m", propose=stub)
check("outcome is 'reverted'", out == "reverted")
check("file restored (no KEPTMARK)", "KEPTMARK" not in open(os.path.join(AI.ROOT, CONFIRM)).read())
check("file is byte-identical to original", open(os.path.join(AI.ROOT, CONFIRM)).read() == orig)

# cleanup artifacts
import shutil
for p in (".autoimprove_backup",):
    fp = os.path.join(AI.ROOT, p)
    if os.path.isdir(fp): shutil.rmtree(fp)

print("\n" + ("ALL PASS ✅" if ok else "SOME FAILED ❌"))
raise SystemExit(0 if ok else 1)
