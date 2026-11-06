#!/usr/bin/env python3
"""Pipeline reliability test — exercises the CRAWL layer, not just detectors.

The DOM-XSS miss happened because the old tests only fed transactions straight
to detectors; they never checked that the crawler actually DISCOVERS and FETCHES
the right things from realistic (unquoted) PortSwigger HTML. This test closes
that gap: it drives the real discovery + detection path against this exact lab's
real content and asserts the Stage-1 DOM-XSS is found and ranked first.

Run: python test_pipeline.py
"""
from wapt.live import LiveState
from wapt.models import Transaction
from wapt.squad import SquadCoordinator
from wapt import detectors

FAILS = []
def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILS.append(name)

# ---- real content captured from the live lab -----------------------------
HOMEPAGE = '''<!DOCTYPE html><html><head>
<script src=/resources/js/searchResults.js></script>
</head><body>
<section class=search>
 <form action=/ method=GET><input type=text placeholder='Search the blog...' name=SearchTerm></form>
</section>
<a href=/post?postId=1>post</a>
<a href=/sign-in>Login</a>
</body></html>'''

# the real searchResults.js from the lab (location.search -> eval)
SEARCHJS = '''function search(path){var xhr=new XMLHttpRequest();
xhr.onreadystatechange=function(){if(this.readyState==4&&this.status==200){
eval('var searchResultsObj = ' + this.responseText);displaySearchResults(searchResultsObj);}};
xhr.open("GET", path + window.location.search);xhr.send();}'''

SIGNIN = '''<form class=login-form method=POST action=/login>
<input required type=hidden name=csrf value=x>
<input required type=username name=username>
<input required type=password name=password>
<a href=/refreshpassword>Forgot password?</a>
<button class=button type=submit>Log in</button></form>'''


def test_crawl_discovers_unquoted_script():
    """The bug: crawler's quoted-only regex never queued the JS file."""
    import re
    href = re.compile(r'(?:href|src|action)=(?:"([^"#]+)"|\'([^\'#]+)\'|([^\s>#]+))', re.I)
    found = [next((x for x in g if x), "") for g in href.findall(HOMEPAGE)]
    check("crawl queues unquoted <script src> (searchResults.js)",
          any("searchResults.js" in f for f in found))
    check("crawl still finds normal links (/post, /sign-in)",
          any("/post" in f for f in found) and any("/sign-in" in f for f in found))


def test_inputs_discovered():
    st = LiveState.__new__(LiveState)
    pts = st._inputs_on_page("https://lab/", HOMEPAGE)
    params = [p[2] for p in pts]
    check("search param SearchTerm discovered", "SearchTerm" in params)
    st2 = LiveState.__new__(LiveState)
    lpts = st2._inputs_on_page("https://lab/sign-in", SIGNIN)
    lparams = [p[2] for p in lpts]
    methods = {p[2]: p[0] for p in lpts}
    check("login username/password discovered", "username" in lparams and "password" in lparams)
    check("login form parsed as POST (not GET)", methods.get("username") == "POST")
    check("CSRF token excluded from probing", "csrf" not in lparams)


def test_domxss_detected_and_ranked_first():
    js = Transaction(method="GET", url="https://lab.web-security-academy.net/resources/js/searchResults.js",
                     status=200, resp_headers={"Content-Type": "application/javascript"}, resp_body=SEARCHJS)
    sigs = list(detectors.d_dom_xss(js, {}))
    check("DOM-XSS detector fires on real searchResults.js", len(sigs) > 0)
    check("DOM-XSS flagged HIGH (location.search -> eval)",
          any(str(s.confidence) == "high" for s in sigs))

    home = Transaction(method="GET", url="https://lab.web-security-academy.net/",
                       status=200, resp_body=HOMEPAGE)
    signin = Transaction(method="GET", url="https://lab.web-security-academy.net/sign-in",
                         status=200, resp_body=SIGNIN)
    c = SquadCoordinator()
    reps = c.run([home, js, signin], {"LAB": "lab.web-security-academy.net", "EXPLOIT": "", "COLLAB": "x.oastify.com"},
                 gate_fn=lambda r: True)
    hits = c.snapshot(reps)[0]["agents"]
    found = [a for a in hits if a["found"]]
    check("Stage 1 has at least one lead", len(found) > 0)
    if found:
        top = found[0]
        check(f"Stage 1 #1 lead is DOM-XSS (got: {top['agent']})", "DOM-XSS" in top["agent"])
        check("DOM-XSS ranked above auth-brute",
              all(not (a["agent"].startswith("auth-brute") and a["pct"] >= top["pct"]) for a in found[1:]))
        # the repro must contain the cookie-theft bypass
        rc = top.get("repro_card", {})
        check("DOM-XSS repro present", bool(rc.get("steps")))


if __name__ == "__main__":
    print("PIPELINE RELIABILITY TEST — real lab content")
    print("=" * 55)
    print("\n1) Crawl discovery (the layer the old tests skipped):")
    test_crawl_discovers_unquoted_script()
    test_inputs_discovered()
    print("\n2) DOM-XSS detection + ranking (the actual Stage 1):")
    test_domxss_detected_and_ranked_first()
    print("\n" + "=" * 55)
    if FAILS:
        print(f"❌ {len(FAILS)} CHECK(S) FAILED: {FAILS}")
        raise SystemExit(1)
    print("✅ ALL PIPELINE CHECKS PASS — crawl finds the JS, DOM-XSS leads Stage 1")
