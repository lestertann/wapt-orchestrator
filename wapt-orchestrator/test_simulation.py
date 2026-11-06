#!/usr/bin/env python3
"""Full BSCP coverage simulation — every vuln class through the real squad.

For each of the 26 specialist agents we build a realistic transaction that
matches how the tool would capture that vuln after crawling/probing, run it
through the per-stage SquadCoordinator, and assert the right agent reports a
lead. This is the UAT: it proves each class is actually identified end-to-end,
not just that a detector function exists.

Run: python test_simulation.py
"""
from wapt.models import Stage, Transaction
from wapt.squad import SquadCoordinator

PH = {"LAB": "lab.web-security-academy.net", "EXPLOIT": "exp.net", "COLLAB": "c.oastify.com"}
FAILS = []


def T(**kw):
    kw.setdefault("status", 200)
    kw.setdefault("req_headers", {})
    kw.setdefault("resp_headers", {})
    kw.setdefault("req_body", "")
    kw.setdefault("resp_body", "")
    return Transaction(**kw)


# (stage, expected vuln_class, fixture transaction) ------------------------
FIXTURES = [
    # ---------------- STAGE 1 : FOOTHOLD ----------------
    (Stage.FOOTHOLD, "dom-xss", T(
        method="GET", url="https://lab.web-security-academy.net/resources/js/searchResults.js",
        resp_headers={"Content-Type": "application/javascript"},
        resp_body='xhr.open("GET", path + window.location.search);'
                  'eval("var o = " + this.responseText);')),
    (Stage.FOOTHOLD, "web-message-xss", T(
        method="GET", url="https://lab.web-security-academy.net/",
        resp_body='<script>window.addEventListener("message", function(e){'
                  'document.body.innerHTML = e.data;});</script>')),
    (Stage.FOOTHOLD, "reflected-stored-xss", T(
        method="GET", url="https://lab.web-security-academy.net/?search=wapttest12",
        resp_body='<h1>0 results for wapttest12</h1>')),
    (Stage.FOOTHOLD, "host-header", T(
        method="POST", url="https://lab.web-security-academy.net/forgot-password",
        req_headers={"X-Forwarded-Host": "wapt9z.evil"},
        resp_body='reset link: https://wapt9z.evil/reset?token=x')),
    (Stage.FOOTHOLD, "cache-poisoning", T(
        method="GET", url="https://lab.web-security-academy.net/resources/app.js",
        resp_headers={"X-Cache": "hit", "Content-Type": "application/javascript"},
        resp_body="console.log(1)")),
    (Stage.FOOTHOLD, "request-smuggling", T(
        method="POST", url="https://lab.web-security-academy.net/",
        req_headers={"Transfer-Encoding": "chunked", "Content-Length": "6"})),
    (Stage.FOOTHOLD, "user-enum-brute", T(
        method="GET", url="https://lab.web-security-academy.net/sign-in",
        resp_body='<form method=POST action=/login><input type=username name=username>'
                  '<input type=password name=password><a href=/refreshpassword>Forgot?</a></form>')),
    (Stage.FOOTHOLD, "oauth-takeover", T(
        method="GET", url="https://lab.web-security-academy.net/oauth/authorize?client_id=123&redirect_uri=https://lab/cb&response_type=code")),
    (Stage.FOOTHOLD, "cswsh", T(
        method="GET", url="https://lab.web-security-academy.net/chat", status=101,
        resp_headers={"Upgrade": "websocket"})),
    (Stage.FOOTHOLD, "content-discovery", T(
        method="GET", url="https://lab.web-security-academy.net/metrics", status=403,
        resp_body="Forbidden")),

    # ---------------- STAGE 2 : PRIVESC ----------------
    (Stage.PRIVESC, "sql-injection", T(
        method="GET", url="https://lab.web-security-academy.net/filter?category=Gifts'",
        resp_body="You have an error in your SQL syntax near ''")),
    (Stage.PRIVESC, "jwt-forge", T(
        method="GET", url="https://lab.web-security-academy.net/my-account",
        req_headers={"Cookie": "session=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ3aWVuZXIifQ."})),
    (Stage.PRIVESC, "idor-mass-assign", T(
        method="GET", url="https://lab.web-security-academy.net/my-account",
        resp_headers={"Content-Type": "application/json"},
        resp_body='{"username":"wiener","roleid":1}')),
    (Stage.PRIVESC, "csrf-takeover", T(
        method="POST", url="https://lab.web-security-academy.net/my-account/change-email",
        req_body="email=foo@bar.com")),
    (Stage.PRIVESC, "password-reset-logic", T(
        method="POST", url="https://lab.web-security-academy.net/reset-password?token=abc123",
        req_body="new-password=foo")),
    (Stage.PRIVESC, "cors-exfil", T(
        method="GET", url="https://lab.web-security-academy.net/api/key",
        req_headers={"Origin": "https://evil.net"},
        resp_headers={"Access-Control-Allow-Origin": "https://evil.net",
                      "Access-Control-Allow-Credentials": "true"})),
    (Stage.PRIVESC, "api-graphql", T(
        method="POST", url="https://lab.web-security-academy.net/graphql",
        req_body='{"query":"{__schema{types{name}}}"}')),
    (Stage.PRIVESC, "client-side-proto-pollution", T(
        method="GET", url="https://lab.web-security-academy.net/?__proto__[x]=y")),

    # ---------------- STAGE 3 : EXFIL ----------------
    (Stage.EXFIL, "os-command-injection", T(
        method="GET", url="https://lab.web-security-academy.net/image?filename=x&imageSize=100x100",
        resp_body="img")),
    (Stage.EXFIL, "path-traversal", T(
        method="GET", url="https://lab.web-security-academy.net/image?filename=cat.jpg")),
    (Stage.EXFIL, "ssti", T(
        method="GET", url="https://lab.web-security-academy.net/edit-email-template")),
    (Stage.EXFIL, "xxe", T(
        method="POST", url="https://lab.web-security-academy.net/product/stock",
        req_headers={"Content-Type": "application/xml"},
        req_body='<?xml version="1.0"?><stockCheck><productId>1</productId></stockCheck>')),
    (Stage.EXFIL, "ssrf", T(
        method="POST", url="https://lab.web-security-academy.net/product/stock",
        req_body="stockApi=http://stock.internal/check")),
    (Stage.EXFIL, "file-upload-rce", T(
        method="POST", url="https://lab.web-security-academy.net/my-account/avatar",
        req_headers={"Content-Type": "multipart/form-data; boundary=x"},
        req_body="--x--")),
    (Stage.EXFIL, "deserialization", T(
        method="GET", url="https://lab.web-security-academy.net/my-account",
        req_headers={"Cookie": "session=rO0ABXNyABFqYXZh"})),
    (Stage.EXFIL, "server-side-proto-pollution", T(
        method="POST", url="https://lab.web-security-academy.net/my-account",
        req_headers={"Content-Type": "application/json"},
        req_body='{"user":"x","__proto__":{"isAdmin":true}}')),
]


def run():
    print("BSCP COVERAGE SIMULATION — 26 classes through the real squad")
    print("=" * 62)
    # group fixtures by stage, run the squad once per stage with ALL its
    # fixtures present (realistic: many signals at once; tests nothing is dropped)
    by_stage = {}
    for stage, cls, txn in FIXTURES:
        by_stage.setdefault(stage, {"txns": [], "want": []})
        by_stage[stage]["txns"].append(txn)
        by_stage[stage]["want"].append(cls)

    coord = SquadCoordinator()
    for stage in (Stage.FOOTHOLD, Stage.PRIVESC, Stage.EXFIL):
        data = by_stage[stage]
        reps = coord.run(data["txns"], PH, gate_fn=lambda r: True)
        snap = coord.snapshot(reps)
        stage_snap = next(s for s in snap if s["stage"] == stage.name)
        found = {a["class"] for a in stage_snap["agents"] if a["found"]}
        print(f"\nSTAGE {int(stage)} — {stage.title}")
        for cls in data["want"]:
            ok = cls in found
            print(f"  [{'PASS' if ok else 'FAIL'}] {cls}")
            if not ok:
                FAILS.append(f"{stage.name}:{cls}")

    print("\n" + "=" * 62)
    total = len(FIXTURES)
    print(f"Coverage: {total - len(FAILS)}/{total} classes identified")
    if FAILS:
        print(f"❌ MISSED: {FAILS}")
        raise SystemExit(1)
    print("✅ ALL 26 CLASSES IDENTIFIED END-TO-END")


if __name__ == "__main__":
    run()
