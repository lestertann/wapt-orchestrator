#!/usr/bin/env python3
"""End-to-end test of LIVE mode without Burp: start the server in a thread,
POST synthetic transactions to /ingest exactly like the extension would, poll
/api/state, click Proceed, and assert the stage board behaves.
"""
import json, threading, time, urllib.request as U
from wapt.config import Config
from wapt import live

PORT = 8799
BASE = f"http://127.0.0.1:{PORT}"


def post(path, obj):
    r = U.Request(BASE + path, data=json.dumps(obj).encode(),
                  headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(U.urlopen(r, timeout=3).read())


def get(path):
    return json.loads(U.urlopen(BASE + path, timeout=3).read())


STREAM = [
    {"method": "GET", "url": "https://lab.web-security-academy.net/?search=hello",
     "status": 200, "resp_headers": {"Content-Type": "text/html"},
     "resp_body": "<p>no results for hello</p>"},
    {"method": "GET", "url": "https://lab.web-security-academy.net/js/app.js",
     "status": 200, "resp_headers": {"Content-Type": "application/javascript"},
     "resp_body": "x=location.hash;document.write(x)"},
    {"method": "POST", "url": "https://lab.web-security-academy.net/my-account/change-email",
     "req_headers": {"Content-Type": "application/json", "Cookie": "TrackingId=zz"},
     "req_body": '{"email":"a@b.c"}', "status": 200,
     "resp_headers": {"Content-Type": "application/json"},
     "resp_body": '{"username":"wiener","roleid":7}'},
    {"method": "POST", "url": "https://lab.web-security-academy.net/stock",
     "req_headers": {"Content-Type": "application/xml"},
     "req_body": "<stockCheck><productId>1</productId></stockCheck>",
     "status": 200, "resp_headers": {}, "resp_body": "5"},
]


def main():
    cfg = Config(lab="lab.web-security-academy.net", collab="c.oastify.com",
                 exploit="e.exploit-server.net", proxy=None, mode="engagement")
    cfg.scope = ["lab.web-security-academy.net"]

    state = live.LiveState(cfg)
    from http.server import ThreadingHTTPServer
    httpd = ThreadingHTTPServer((cfg_host := "127.0.0.1", PORT), live.make_handler(state))
    th = threading.Thread(target=httpd.serve_forever, daemon=True); th.start()
    time.sleep(0.3)

    ok = True
    def check(name, cond):
        nonlocal ok; ok = ok and cond
        print(("  PASS " if cond else "  FAIL ") + name)

    print("\n--- live-mode assertions ---")
    # dashboard serves
    html = U.urlopen(BASE + "/", timeout=3).read().decode()
    check("dashboard page serves", "wapt · orchestrator" in html)

    # stream in traffic like the extension does
    for t in STREAM:
        post("/ingest", t)
    # also test a batch post + an out-of-scope drop
    r = post("/ingest", [{"method": "GET", "url": "https://evil.example/x", "status": 200}])
    check("out-of-scope txn dropped", r["added"] == 0)

    s = get("/api/state")
    check("stage starts at 1", s["stage"] == 1)
    check("txns counted (4 in-scope)", s["txns"] == 4)
    cls1 = {c["vuln_class"] for c in s["candidates"]}
    check("stage 1 shows reflected XSS", "reflected-stored-xss" in cls1)
    check("stage 1 shows DOM XSS", "dom-xss" in cls1)
    check("engagement mode hides exploit bodies",
          all(not (p["kind"] == "exploit" and c["show_exploit"]) for c in s["candidates"] for p in c["payloads"]))
    check("candidates carry lab links", all(c["labs"] for c in s["candidates"]))

    # proceed to stage 2
    s2 = post("/api/proceed", {})
    check("proceed advanced to stage 2", s2["stage"] == 2)
    cls2 = {c["vuln_class"] for c in s2["candidates"]}
    check("stage 2 shows SQLi (TrackingId)", "sql-injection" in cls2)
    check("stage 2 shows mass-assign (roleid)", "idor-mass-assign" in cls2)

    # proceed to stage 3
    s3 = post("/api/proceed", {})
    check("proceed advanced to stage 3", s3["stage"] == 3)
    check("stage 3 is final (can't advance)", s3["can_advance"] is False)
    check("stage 3 shows XXE", "xxe" in {c["vuln_class"] for c in s3["candidates"]})

    # live streaming after advancing: a new stage-3 bug shows up without reset
    post("/ingest", {"method": "GET",
         "url": "https://lab.web-security-academy.net/admin/img?imageFileName=a.jpg&ImgSize=9",
         "status": 200, "resp_headers": {"Content-Type": "image/jpeg"}, "resp_body": ""})
    s3b = get("/api/state")
    check("new traffic triaged live into current stage",
          "os-command-injection" in {c["vuln_class"] for c in s3b["candidates"]})

    # reset
    sr = post("/api/reset", {})
    check("reset clears + returns to stage 1", sr["stage"] == 1 and sr["txns"] == 0)

    httpd.shutdown()
    print("\n" + ("ALL PASS ✅" if ok else "SOME FAILED ❌"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
