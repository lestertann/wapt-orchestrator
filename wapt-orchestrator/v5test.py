#!/usr/bin/env python3
"""v5 tests: zero-config auto-detect, browser setup wizard, DO-THIS-NOW next
action, and autopilot auto-confirm. Run: python3 v5test.py"""
import threading, time, json, urllib.request as U
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from wapt.config import Config
from wapt import live

ok = True
def check(n, c):
    global ok; ok = ok and c
    print(("  PASS " if c else "  FAIL ") + n)

# ---- mock BSCP-ish target with a boolean/error SQLi in SearchTerm ----
class Mock(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        t = parse_qs(urlparse(self.path).query, keep_blank_values=True).get("SearchTerm",[""])[0]
        if t.endswith("'") and "UNION" not in t:
            body = '{"error":"SQL syntax error near"}'
        elif "UNION SELECT" in t:
            nulls = t.split("UNION SELECT",1)[1].split("--")[0]
            body = '{"results":[{"x":"administrator s3cr3t"}]}' if nulls.count(",")+1==4 and "username" in nulls \
                   else ('{"results":[{"x":"' + ("M" if ("'M'" in nulls) else "") + '"}]}' if nulls.count(",")+1==4 else '{"error":"cols"}')
        else:
            body = '{"results":[1,2,3]}'
        b=body.encode(); self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)

MPORT = 8866
ThreadingHTTPServer(("127.0.0.1",MPORT), Mock)  # noqa (we start a real one below for probes)
mock = ThreadingHTTPServer(("127.0.0.1",MPORT), Mock)
threading.Thread(target=mock.serve_forever, daemon=True).start()

# ---- live server, NO lab/collab preset (zero-config) ----
cfg = Config(proxy=None, mode="lab", profile="bscp")   # nothing set!
st = live.LiveState(cfg)
SPORT = 8867
srv = ThreadingHTTPServer(("127.0.0.1",SPORT), live.make_handler(st))
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.2)

def post(p,o):
    r=U.Request(f"http://127.0.0.1:{SPORT}"+p, data=json.dumps(o).encode(),
                headers={"Content-Type":"application/json"}, method="POST")
    return json.loads(U.urlopen(r,timeout=5).read())
def state(): return json.loads(U.urlopen(f"http://127.0.0.1:{SPORT}/api/state",timeout=5).read())

print("\n--- zero-config auto-detect ---")
# ingest a page from a web-security-academy.net host with an exploit-server link in the body
post("/ingest", {"method":"GET","url":"https://0aXX.web-security-academy.net/",
     "status":200,"resp_headers":{"Content-Type":"text/html"},
     "resp_body":"<a href='https://exploit-0aYY.exploit-server.net'>exploit</a>"})
s = state()
check("LAB auto-detected from traffic", s["lab"] == "0aXX.web-security-academy.net")
check("exploit server auto-detected from page", s["exploit"] == "exploit-0aYY.exploit-server.net")
check("still needs setup (no Collaborator yet)", s["needs_setup"] is True)
check("next action tells beginner what to do", bool(s["next_action"]["headline"]))

print("\n--- browser setup wizard ---")
s = post("/api/setup", {"collab":"abcd.oastify.com/"})   # trailing slash on purpose
check("Collaborator saved (normalized)", s["collab"] == "abcd.oastify.com")
check("setup no longer needed", s["needs_setup"] is False)

print("\n--- autopilot auto-confirm (no manual Confirm clicks) ---")
# point scope at the mock so probes can actually run, ingest a SQLi-looking txn
st.cfg.scope = ["127.0.0.1", "web-security-academy.net"]
st.cfg.lab = "127.0.0.1"
post("/ingest", {"method":"GET","url":f"http://127.0.0.1:{MPORT}/search_res?SearchTerm=hello",
     "status":200,"resp_headers":{"Content-Type":"application/json"},
     "req_headers":{"Cookie":"TrackingId=zz"}})
post("/api/proceed", {})   # move to Stage 2 where SQLi lives
check("autopilot is ON by default in lab mode", state()["autopilot"] is True)
# let the background worker tick a few times
confirmed = False
for _ in range(20):
    time.sleep(1.0)
    s = state()
    if any(c["confirmed"] for c in s["candidates"] if c["vuln_class"]=="sql-injection"):
        confirmed = True; break
check("SQLi auto-confirmed by autopilot (no click)", confirmed)
na = state()["next_action"]
check("next action gives step-by-step plan once confirmed",
      ("real" in na["headline"].lower()) and bool(na.get("steps")) and bool(na.get("payload")))

print("\n--- autopilot can be turned off ---")
s = post("/api/autopilot", {"on": False})
check("autopilot toggled off", s["autopilot"] is False)

srv.shutdown(); mock.shutdown()
print("\n" + ("ALL PASS ✅" if ok else "SOME FAILED ❌"))
raise SystemExit(0 if ok else 1)
