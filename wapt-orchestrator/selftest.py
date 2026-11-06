#!/usr/bin/env python3
"""Hermetic self-test: synthetic traffic with one planted bug per stage, an
injected gate that stops after Stage 1, and assertions that triage + gating work.
No network, no Burp, no sample file needed.  Run:  python3 selftest.py
"""
from wapt.config import Config
from wapt.engine import Orchestrator
from wapt.models import Stage, Transaction


def planted_traffic():
    return [
        # Stage 1: reflected param + a DOM sink script + an OAuth flow w/o state
        Transaction("GET", "https://lab.web-security-academy.net/?search=tracktest",
                    status=200, resp_headers={"Content-Type": "text/html"},
                    resp_body="<h1>0 results for tracktest</h1>"),
        Transaction("GET", "https://lab.web-security-academy.net/js/app.js",
                    status=200, resp_headers={"Content-Type": "application/javascript"},
                    resp_body="var q=location.search; document.getElementById('x').innerHTML=q;"),
        Transaction("GET", "https://lab.web-security-academy.net/auth?client_id=1&redirect_uri=https://cb&response_type=token",
                    status=302, resp_headers={}, resp_body=""),
        # Stage 2: roleid leak + TrackingId cookie + a JWT
        Transaction("POST", "https://lab.web-security-academy.net/my-account/change-email",
                    req_headers={"Content-Type": "application/json", "Cookie": "TrackingId=abc123"},
                    req_body='{"email":"x@x.com"}', status=200,
                    resp_headers={"Content-Type": "application/json"},
                    resp_body='{"username":"wiener","email":"x@x.com","roleid":12}'),
        Transaction("GET", "https://lab.web-security-academy.net/my-account",
                    req_headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3aWVuZXIifQ.sig"},
                    status=200, resp_headers={}, resp_body="hi"),
        # Stage 3: XML upload body + an image size param + an SSRF url param
        Transaction("POST", "https://lab.web-security-academy.net/stock",
                    req_headers={"Content-Type": "application/xml"},
                    req_body="<stockCheck><productId>1</productId></stockCheck>",
                    status=200, resp_headers={}, resp_body="99"),
        Transaction("GET", "https://lab.web-security-academy.net/admin/image?imageFileName=1.jpg&ImgSize=120",
                    status=200, resp_headers={"Content-Type": "image/jpeg"}, resp_body=""),
        Transaction("POST", "https://lab.web-security-academy.net/admin/report",
                    req_headers={"Content-Type": "application/json"},
                    req_body='{"PageHtml":"x","url":"https://x/"}', status=200,
                    resp_headers={}, resp_body="ok"),
    ]


def main():
    cfg = Config(lab="lab.web-security-academy.net", exploit="ex.exploit-server.net",
                 collab="c.oastify.com", proxy=None, mode="engagement")
    cfg.scope = ["lab.web-security-academy.net"]

    # injected gate: say NO at the first gate, so we stop after Stage 1
    gate_calls = []
    def gate(stage, nxt):
        gate_calls.append(int(stage))
        return False   # decline -> engine should stop

    orch = Orchestrator(cfg, gate_fn=gate)
    # disable live confirm for a hermetic run
    orch.session.sess = None
    results = orch.run(planted_traffic(), auto_proceed=False)

    # ---- assertions ----
    ok = True
    def check(name, cond):
        nonlocal ok
        print(("  PASS " if cond else "  FAIL ") + name)
        ok = ok and cond

    print("\n--- self-test assertions ---")
    s1 = results[Stage.FOOTHOLD]
    classes1 = {c.vuln_class for c in s1.candidates}
    check("stage 1 ran", Stage.FOOTHOLD in results)
    check("stage 1 found reflected XSS", "reflected-stored-xss" in classes1)
    check("stage 1 found DOM XSS", "dom-xss" in classes1)
    check("stage 1 found OAuth (no state)", "oauth-takeover" in classes1)
    check("gate was asked after stage 1", gate_calls == [1])
    check("engine STOPPED after declined gate (no stage 2)", Stage.PRIVESC not in results)

    # now run with auto to prove all three stages + planted bugs
    orch2 = Orchestrator(cfg, gate_fn=lambda s, n: True)
    orch2.session.sess = None
    r2 = orch2.run(planted_traffic(), auto_proceed=True)
    c2 = {c.vuln_class for c in r2[Stage.PRIVESC].candidates}
    c3 = {c.vuln_class for c in r2[Stage.EXFIL].candidates}
    check("stage 2 found mass-assign (roleid leak)", "idor-mass-assign" in c2)
    check("stage 2 found SQLi (TrackingId)", "sql-injection" in c2)
    check("stage 2 found JWT", "jwt-forge" in c2)
    check("stage 3 found XXE (xml body)", "xxe" in c3)
    check("stage 3 found OS cmd injection (ImgSize)", "os-command-injection" in c3)
    check("stage 3 found SSRF (url param)", "ssrf" in c3)
    # the FPs we fixed must NOT be present from this clean traffic
    check("no false XXE on non-xml", all(
        "svg" not in cc.location for cc in r2[Stage.EXFIL].candidates if cc.vuln_class == "xxe"))
    # every candidate carries payloads + lab links
    allc = [c for r in r2.values() for c in r.candidates]
    check("every candidate has >=1 payload", all(c.payloads for c in allc))
    check("every candidate has lab links", all(c.labs for c in allc))

    print("\n" + ("ALL PASS ✅" if ok else "SOME FAILED ❌"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
