#!/usr/bin/env python3
"""Tests for the v3 improvements: FP suppression, tailored payloads, and the
active confirmation engine (run against a mock vulnerable server, no Burp).
"""
import json, threading, time, urllib.request as U
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from wapt.config import Config
from wapt.models import Stage, Transaction
from wapt.triage import triage
from wapt.http_client import ScopedSession
from wapt import confirm as CF

ok = True
def check(name, cond):
    global ok; ok = ok and cond
    print(("  PASS " if cond else "  FAIL ") + name)


# --------------------------------------------------------------------------- #
# 1. FP suppression (pure triage, no network)
# --------------------------------------------------------------------------- #
print("\n--- FP suppression ---")
ph = {"LAB": "lab.net", "EXPLOIT": "ex.net", "COLLAB": "c.oastify.com"}

# lab-status websocket must NOT be flagged as CSWSH
labws = Transaction("GET", "https://lab.net/academyLabHeader", status=101,
                    req_headers={"Upgrade": "websocket"}, resp_headers={})
c = triage(Stage.FOOTHOLD, [labws], ph)
check("lab-header websocket suppressed (no CSWSH)",
      "cswsh" not in {x.vuln_class for x in c})

# blog post "id":5 in search results must NOT be mass-assignment
blog = Transaction("GET", "https://lab.net/search_res?SearchTerm=x", status=200,
                   resp_headers={"Content-Type": "application/json"},
                   resp_body='{"results":[{"id":5,"title":"t"}]}')
c = triage(Stage.PRIVESC, [blog], ph)
check("blog-post id suppressed (no mass-assign FP)",
      "idor-mass-assign" not in {x.vuln_class for x in c})

# a real roleid on an account endpoint IS still flagged
acct = Transaction("POST", "https://lab.net/my-account/change-email", status=200,
                   req_headers={"Content-Type": "application/json"},
                   resp_headers={"Content-Type": "application/json"},
                   resp_body='{"username":"w","roleid":7}')
c = triage(Stage.PRIVESC, [acct], ph)
check("real roleid on account endpoint still flagged",
      "idor-mass-assign" in {x.vuln_class for x in c})

# csrf-token reflection must NOT be reflected-XSS
csrfrefl = Transaction("GET", "https://lab.net/sign-in?csrf=AbCdEf123456", status=200,
                       resp_headers={"Content-Type": "text/html"},
                       resp_body='<input name=csrf value="AbCdEf123456">')
c = triage(Stage.FOOTHOLD, [csrfrefl], ph)
check("csrf-token reflection suppressed (no XSS FP)",
      "reflected-stored-xss" not in {x.vuln_class for x in c})


# --------------------------------------------------------------------------- #
# 2. Tailored payloads carry the REAL param + endpoint
# --------------------------------------------------------------------------- #
print("\n--- tailored payloads ---")
reflect = Transaction("GET", "https://lab.net/search?SearchTerm=hello", status=200,
                      resp_headers={"Content-Type": "text/html"},
                      resp_body="results for hello")
c = triage(Stage.FOOTHOLD, [reflect], ph)
rx = next((x for x in c if x.vuln_class == "reflected-stored-xss"), None)
check("reflected-xss candidate tailored", rx is not None and len(rx.tailored) > 0)
if rx:
    joined = " ".join(p.body for p in rx.tailored)
    check("tailored uses real param SearchTerm (not ?search=)",
          "SearchTerm=" in joined and rx.param == "SearchTerm")
    check("tailored uses real endpoint /search", "/search?" in joined)


# --------------------------------------------------------------------------- #
# 3. Active confirmation against a MOCK vulnerable server
# --------------------------------------------------------------------------- #
print("\n--- active confirmation (mock target) ---")

class Mock(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        term = qs.get("SearchTerm", [""])[0]
        # emulate a boolean-based SQLi in SearchTerm:
        #   baseline / TRUE  -> full list ; FALSE / broken -> empty
        if "'1'='2" in term:
            body = '{"results":[]}'                      # FALSE -> empty
        elif "'1'='1" in term:
            body = '{"results":[1,2,3,4,5,6,7,8,9,10]}'  # TRUE  -> full
        elif term.endswith("'"):
            body = '{"error":"You have an error in your SQL syntax"}'  # quote -> error
        else:
            body = '{"results":[1,2,3,4,5,6,7,8,9,10]}'  # baseline -> full
        b = body.encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)

PORT = 8811
httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Mock)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
time.sleep(0.2)

cfg = Config(lab="127.0.0.1", collab="c.oastify.com", proxy=None, mode="lab")
cfg.scope = ["127.0.0.1"]
sess = ScopedSession(cfg)

txn = Transaction("GET", f"http://127.0.0.1:{PORT}/search_res?SearchTerm=hello",
                  status=200, resp_headers={"Content-Type": "application/json"})
v = CF.confirm_sqli(sess, txn, "SearchTerm")
check("confirm_sqli returns a verdict", v is not None)
check("mock SQLi CONFIRMED", v.ok is True)
check("verdict names the param", "SearchTerm" in v.label)
print("        verdict:", v.as_note())

# negative: a param with no SQLi must not be confirmed
txn2 = Transaction("GET", f"http://127.0.0.1:{PORT}/search_res?other=1",
                   status=200, resp_headers={"Content-Type": "application/json"})
# 'other' isn't handled by mock -> baseline==quote==boolean, no oracle
v2 = CF.confirm_sqli(sess, txn2, "other")
check("non-injectable param NOT confirmed", v2.ok is False)

httpd.shutdown()
print("\n" + ("ALL PASS ✅" if ok else "SOME FAILED ❌"))
raise SystemExit(0 if ok else 1)
