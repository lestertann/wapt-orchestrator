#!/usr/bin/env python3
"""Tests for v4: config host-normalization, auto-UNION builder, Markdown report
+ probe audit log. Run: python3 v4test.py"""
import threading, time, argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from wapt.config import Config
from wapt.http_client import ScopedSession
from wapt import confirm as CF, report
from wapt.models import Transaction, Stage, StageResult, Candidate

ok = True
def check(n, c):
    global ok; ok = ok and c
    print(("  PASS " if c else "  FAIL ") + n)

print("\n--- config host-normalization ---")
ns = argparse.Namespace(config=None, lab="https://0aXX.web-security-academy.net/",
                        exploit="exploit-0aYY.exploit-server.net", collab="c.oastify.com/",
                        mode=None, profile=None, proxy=None, no_proxy=False, scope=None,
                        rate_per_sec=None, timeout=None)
c = Config.from_args_and_env(ns)
check("strips https:// and trailing / from lab", c.lab == "0aXX.web-security-academy.net")
check("strips trailing / from collab", c.collab == "c.oastify.com")

print("\n--- auto-UNION builder (4-col mock, text cols 2 & 4) ---")
class Mock(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        t = parse_qs(urlparse(self.path).query, keep_blank_values=True).get("SearchTerm",[""])[0]
        if "UNION SELECT" in t:
            nulls = t.split("UNION SELECT",1)[1].split("--")[0]
            if nulls.count(",")+1 != 4:
                body = '{"error":"SQL syntax"}'
            else:
                shown = "administrator s3cr3t" if "username" in nulls else \
                        " ".join(p.strip().strip("'") for i,p in enumerate(nulls.split(",")) if i in (1,3) and p.strip()!="NULL")
                body = '{"results":[{"x":"'+shown+'"}]}'
        elif t.endswith("'"): body = '{"error":"SQL syntax error near"}'
        else: body = '{"results":[1,2,3]}'
        b=body.encode(); self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)

h = ThreadingHTTPServer(("127.0.0.1",8855), Mock); threading.Thread(target=h.serve_forever,daemon=True).start(); time.sleep(.2)
cfg = Config(lab="127.0.0.1", collab="c.oastify.com", proxy=None, mode="lab"); cfg.scope=["127.0.0.1"]
s = ScopedSession(cfg)
txn = Transaction("GET","http://127.0.0.1:8855/search_res?SearchTerm=hello",status=200,resp_headers={"Content-Type":"application/json"})
v = CF.confirm_sqli(s, txn, "SearchTerm")
check("SQLi confirmed", v.ok)
u = CF.build_union(s, txn, "SearchTerm")
check("auto-UNION found 4 columns", u and u["columns"] == 4)
check("auto-UNION found text columns 2 & 4", u and u["text_columns"] == [2,4])
check("ready payload selects username+password FROM users",
      u and "username" in u["payload"] and "password" in u["payload"] and "users" in u["payload"])

print("\n--- probe audit log + report ---")
check("every probe was logged", len(s.probe_log) > 0)
check("probe log lines are timestamped", ":" in s.probe_log[0].line())
cand = Candidate(vuln_class="sql-injection", title="SQL injection", stage=Stage.PRIVESC,
                 confidence=4, location=txn.url, param="SearchTerm",
                 confirmed=True, confirm_note=v.as_note())
md = report.markdown({Stage.PRIVESC: StageResult(stage=Stage.PRIVESC, candidates=[cand])},
                     "127.0.0.1", "lab", probe_log=s.probe_log)
check("report has a findings header", "# WAPT findings" in md)
check("report marks confirmed", "CONFIRMED" in md)
check("report embeds the audit log", "Probe audit log" in md)
h.shutdown()

print("\n" + ("ALL PASS ✅" if ok else "SOME FAILED ❌"))
raise SystemExit(0 if ok else 1)
