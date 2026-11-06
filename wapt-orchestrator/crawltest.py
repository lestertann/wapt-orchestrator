#!/usr/bin/env python3
"""Test the live auto-crawler: follows same-origin links, skips logout/destructive,
feeds the triage board, and respects the scheme it sees."""
import threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from wapt.config import Config
from wapt import live
from wapt.models import Transaction

ok = True
def check(n, c):
    global ok; ok = ok and c
    print(("  PASS " if c else "  FAIL ") + n)


class Site(BaseHTTPRequestHandler):
    def log_message(s, *a): pass
    def do_GET(s):
        p = s.path
        body = {
            "/": '<a href="/about">a</a> <a href="/search?search=hi">s</a> <a href="/logout">x</a>',
            "/about": '<h1>about</h1><a href="/contact">c</a>',
            "/contact": "<h1>contact</h1>",
        }.get(p.split("?")[0], "<h1>results for hi</h1>")
        b = body.encode(); s.send_response(200); s.send_header("Content-Type", "text/html")
        s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)


srv = ThreadingHTTPServer(("127.0.0.1", 8702), Site)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.1)

cfg = Config(lab="127.0.0.1:8702", collab="c.oastify.com", proxy=None, mode="lab", profile="generic")
cfg.scope = ["127.0.0.1"]
st = live.LiveState(cfg)

print("\n--- auto-crawl on first detection (no manual effort) ---")
# just seeing one page should auto-kick a crawl (autopilot on in lab mode)
st.add(Transaction("GET", "http://127.0.0.1:8702/", status=200,
                   resp_headers={"Content-Type": "text/html"}, resp_body="seed"))
check("auto-crawl triggered by first traffic", st._autocrawled is True)
for _ in range(50):
    time.sleep(0.3)
    if not st._crawling and st.crawl_pages > 0:
        break
eps = {u.split(":8702")[-1] for u in st.seen_urls}
check("crawled multiple pages on its own", st.crawl_pages >= 4)
check("followed links (/about,/contact,/search)", {"/about", "/contact", "/search"} <= eps)
check("logout/destructive skipped", not any("logout" in u for u in st.seen_urls))
check("crawl finished (flag cleared)", st._crawling is False)
check("manual re-crawl allowed after finish", st.start_crawl().get("ok"))
st._crawling = False
srv.shutdown()

print("\n" + ("ALL PASS ✅" if ok else "SOME FAILED ❌"))
raise SystemExit(0 if ok else 1)
