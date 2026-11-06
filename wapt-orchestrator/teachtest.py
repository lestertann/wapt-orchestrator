#!/usr/bin/env python3
"""Teach Me + learning-progress tests."""
import threading, time, json, urllib.request as U
from http.server import ThreadingHTTPServer
from wapt import teach as T
from wapt.config import Config
from wapt import live

ok = True
def check(n, c):
    global ok; ok = ok and c
    print(("  PASS " if c else "  FAIL ") + n)

print("\n--- lesson schema (all classes) ---")
classes = ["sql-injection", "reflected-stored-xss", "dom-xss", "ssrf", "path-traversal",
           "xxe", "ssti", "jwt-forge", "idor-mass-assign", "csrf-takeover"]
good = True
for c in classes:
    l = T.lesson(c)
    if not (l.get("ioc") and l.get("why") and l.get("tell")
            and l["quiz"]["q"] and len(l["quiz"]["options"]) >= 2
            and isinstance(l["quiz"]["answer"], int)
            and 0 <= l["quiz"]["answer"] < len(l["quiz"]["options"]) and l["quiz"]["explain"]):
        good = False; print("   bad schema:", c)
check("every lesson has ioc/why/tell + valid MC quiz", good)
check("answer index points at a real option (all)",
      all(0 <= T.lesson(c)["quiz"]["answer"] < len(T.lesson(c)["quiz"]["options"]) for c in T.LESSONS))
check("teach() alias == lesson()", T.teach("ssrf") == T.lesson("ssrf"))
check("26 patterns catalogued", T.count() == 26)

print("\n--- learning progress tracks in live ---")
cfg = Config(lab="lab.web-security-academy.net", collab="c.oastify.com", proxy=None, mode="lab")
cfg.scope = ["lab.web-security-academy.net"]
st = live.LiveState(cfg)
hd = ThreadingHTTPServer(("127.0.0.1", 8793), live.make_handler(st))
threading.Thread(target=hd.serve_forever, daemon=True).start(); time.sleep(0.2)
def post(p, o):
    return json.loads(U.urlopen(U.Request("http://127.0.0.1:8793" + p, data=json.dumps(o).encode(),
                      headers={"Content-Type": "application/json"})).read())
def state(): return json.loads(U.urlopen("http://127.0.0.1:8793/api/state").read())

post("/ingest", {"method": "GET", "url": "https://lab.web-security-academy.net/search?search=hello",
     "status": 200, "resp_headers": {"Content-Type": "text/html"}, "resp_body": "results for hello"})
s = state()
cand = [c for c in s["candidates"] if c["vuln_class"] == "reflected-stored-xss"][0]
check("candidate carries its teach lesson", bool(cand["teach"]["ioc"]) and bool(cand["teach"]["quiz"]["options"]))
check("learning.seen includes the met pattern", "reflected-stored-xss" in s["learning"]["seen"])
check("learning has total 26", s["learning"]["total"] == 26)
check("report embeds the learning summary", "Patterns learned" in st.report_md())
hd.shutdown()

print("\n" + ("ALL PASS ✅" if ok else "SOME FAILED ❌"))
raise SystemExit(0 if ok else 1)
