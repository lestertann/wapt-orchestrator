#!/usr/bin/env python3
"""Drive the 3 tester personas over one finding per vuln class and aggregate
their feedback into a to-do list (persona_report.md). Exit 1 if any persona
files a HIGH-severity complaint — that's a round's work item.

This is a usability/quality harness, complementary to bench.py (which scores
detection/confirmation correctness). bench.py asks "is it right?"; this asks
"can my three users actually use it?".
"""
from __future__ import annotations

import threading
import time
from collections import Counter
from http.server import ThreadingHTTPServer

from wapt.config import Config
from wapt.triage import triage, TITLES
from wapt import playbook as PB
from wapt import teach as TEACH
from wapt import confirm as CF
from wapt.http_client import ScopedSession
from wapt.live import _AUTO_CONFIRMABLE
from wapt.models import Stage
import personas as P
import labmocks as M
from labs import CATALOG

CF._CMDI_DELAY = 2   # keep the time-based cmdi probe quick


def _cfg():
    c = Config(lab="0aLAB.web-security-academy.net", collab="abc.oastify.com",
               exploit="exploit-0aX.exploit-server.net", mode="lab")
    c.scope = ["web-security-academy.net"]
    return c


def _one_candidate_per_class():
    """Build a representative candidate for every detection scenario's class."""
    cfg = _cfg()
    out = {}
    for sc in CATALOG:
        if sc.kind != "detect" or sc.benign:
            continue
        cands = triage(sc.stage, [sc.txn], cfg.placeholders())
        for c in cands:
            if c.vuln_class == sc.vuln_class and c.vuln_class not in out:
                out[c.vuln_class] = (c, cfg)
    return out


def _confirm_notes():
    """Run each confirm mock once to get a real verdict note per class (so the
    personas see the confirmed-path guidance, incl. SSTI's engine and cmdi timing)."""
    notes, port = {}, 8990
    for sc in CATALOG:
        if sc.kind != "confirm" or sc.benign:
            continue
        srv = ThreadingHTTPServer(("127.0.0.1", port), sc.handler); port += 1
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.03)
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            cfg = Config(lab="127.0.0.1", collab="c.oastify.com", proxy=None, mode="lab")
            cfg.scope = ["127.0.0.1"]
            sess = ScopedSession(cfg)
            url = base + sc.spec["url"].split(".net", 1)[-1]
            txn = sess.fetch("GET", url)
            if sc.spec.get("origin"):
                txn.req_headers["Origin"] = sc.spec["origin"]
                r2 = sess.fetch("GET", url, headers={"Origin": sc.spec["origin"]})
                if r2: txn.resp_headers, txn.resp_body = r2.resp_headers, r2.resp_body
            cands = triage(sc.stage, [txn], cfg.placeholders())
            cand = next((c for c in cands if c.vuln_class == sc.vuln_class), None)
            if cand:
                v = CF.confirm_candidate(sess, cand, collab=cfg.collab)
                if v.ok:
                    notes.setdefault(sc.vuln_class, v.as_note())
        finally:
            srv.shutdown()
    return notes


def _report_check(cands):
    """Build the exported report for a few confirmed findings and make sure the
    recommended action + steps are present — Riz hands this report to a client."""
    from wapt import report as R
    from wapt.models import StageResult, Stage
    f = []
    sample = ["sql-injection", "ssti", "cors-exfil", "path-traversal"]
    buckets = {Stage.FOOTHOLD: [], Stage.PRIVESC: [], Stage.EXFIL: []}
    for cls in sample:
        if cls in cands:
            c, cfg = cands[cls]
            c.confirmed = True
            buckets[c.stage].append(c)
    results = {st: StageResult(stage=st, candidates=cs) for st, cs in buckets.items() if cs}
    _, cfg = next(iter(cands.values()))
    md = R.markdown(results, "lab", "lab", cfg=cfg)
    if "Recommended action" not in md:
        f.append(P.Finding("pentester", "high", "report", "report",
                           "exported report has no 'Recommended action' — only payloads, no plan"))
    if "Steps:" not in md:
        f.append(P.Finding("pentester", "med", "report", "report",
                           "exported report lists no numbered steps for the findings"))
    return f


def _json_api_check():
    """A JSON-body request must still yield injectable params + tailored payloads."""
    from wapt.tailor import context, pick_param
    from wapt.models import Transaction
    f = []
    txn = Transaction("POST", "https://lab.web-security-academy.net/api/search",
                      req_headers={"Content-Type": "application/json"},
                      req_body='{"searchTerm":"gift","category":"x"}',
                      status=200, resp_headers={"Content-Type": "application/json"},
                      resp_body='{"results":[]}')
    _, _, params = context(txn)
    if "searchTerm" not in params:
        f.append(P.Finding("pentester", "high", "sql-injection", "json",
                           "JSON body fields aren't parsed as params — API injection unreachable"))
    return f


def main() -> int:
    cands = _one_candidate_per_class()
    notes = _confirm_notes()
    findings = []
    for cls, (cand, cfg) in sorted(cands.items()):
        cj = {
            "vuln_class": cand.vuln_class, "param": cand.param,
            "tailored": [{"name": p.name, "body": p.body, "kind": p.kind} for p in cand.tailored],
            "labs": cand.labs, "teach": TEACH.teach(cand.vuln_class),
            "_auto_confirmable": cand.vuln_class in _AUTO_CONFIRMABLE,
        }
        note = notes.get(cls)
        if note:
            cand.confirm_note = note.replace("CONFIRMED: ", "")
        pb = PB.build(cand, cfg)
        findings += P.run_all(cj, pb, cfg_set=True, confirmed_note=note)
        # Riz: a confirmed verdict must name a concrete next move, not just "confirmed"
        if note:
            act = ("swap", "use payload", "union", "nslookup", "exfil", "read ",
                   "fetch", "deliver", "boolean", "dump", "secret", "origin", "substring")
            if not any(k in note.lower() for k in act):
                findings.append(P.Finding("pentester", "med", cls, "verdict",
                                          f"confirmed but the note gives no concrete next step: {note[:80]}"))

    # Riz exports the report and checks the plan (not just payloads) made it in
    findings += _report_check(cands)
    # Riz points the tool at a JSON API — param-aware payloads must still work
    findings += _json_api_check()

    by_sev = Counter(f.severity for f in findings)
    by_persona = Counter(f.persona for f in findings)
    highs = [f for f in findings if f.severity == "high"]

    lines = ["# Persona feedback — 3 testers using the orchestrator",
             f"_classes tested: {len(cands)} · findings: {len(findings)} "
             f"(high {by_sev['high']}, med {by_sev['med']}, low {by_sev['low']})_\n",
             f"- Aunty May (beginner): {by_persona['beginner']}",
             f"- Sam (student): {by_persona['student']}",
             f"- Riz (pentester): {by_persona['pentester']}\n"]
    if highs:
        lines.append("## HIGH — fix this round\n")
        for f in highs:
            lines.append(f"- [{f.persona}/{f.cls}/{f.area}] {f.msg}")
    meds = [f for f in findings if f.severity == "med"]
    if meds:
        lines.append("\n## MED\n")
        for f in meds:
            lines.append(f"- [{f.persona}/{f.cls}/{f.area}] {f.msg}")
    lows = [f for f in findings if f.severity == "low"]
    if lows:
        lines.append("\n## LOW\n")
        for f in lows:
            lines.append(f"- [{f.persona}/{f.cls}/{f.area}] {f.msg}")
    open("persona_report.md", "w").write("\n".join(lines))

    print(f"personas: {len(cands)} classes · {len(findings)} findings "
          f"(high {by_sev['high']}, med {by_sev['med']}, low {by_sev['low']})")
    for f in highs:
        print(f"  HIGH [{f.persona}/{f.cls}/{f.area}] {f.msg}")
    for f in meds:
        print(f"  med  [{f.persona}/{f.cls}/{f.area}] {f.msg}")
    print("wrote persona_report.md")
    return 1 if highs else 0


if __name__ == "__main__":
    raise SystemExit(main())
