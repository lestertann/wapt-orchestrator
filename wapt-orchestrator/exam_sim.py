#!/usr/bin/env python3
"""BSCP exam UAT — minimal-knowledge guided-pass simulation + coverage matrix.

Two layers:

  1. COVERAGE MATRIX — one realistic "exam stage" per vuln class, each dropped
     into a bed of benign noise (lab chrome, static assets, a plain page). For
     each, a minimal-knowledge operator must be guided correctly:
        detected · ranked #1 · copy-paste payload · lab links · plain guidance.
     The guided-pass RATE across the whole matrix is reported.

  2. FULL-CHAIN APPS — two end-to-end three-stage apps run through the real
     staged Orchestrator, exam-scored (both apps must pass).

Hermetic (no network / Burp), like selftest.py.  Run:  python3 exam_sim.py
"""
import io
import contextlib

from wapt.config import Config
from wapt.engine import Orchestrator
from wapt.models import Stage, Transaction
from wapt.triage import triage
from wapt import templating as T

PH = {"LAB": "0aXXlab.web-security-academy.net",
      "EXPLOIT": "ex.exploit-server.net", "COLLAB": "c.oastify.com"}
L = "https://0aXXlab.web-security-academy.net"

_GENERIC_WHATIS = "A possible security issue to investigate."
_GENERIC_NEXT = "Open the card below and follow the Detect/Play hints."


def T_(method, url, **kw):
    rh = {}
    if kw.get("cookie"):  rh["Cookie"] = kw["cookie"]
    if kw.get("req_ct"):  rh["Content-Type"] = kw["req_ct"]
    if kw.get("host"):    rh["Host"] = kw["host"]
    if kw.get("origin"):  rh["Origin"] = kw["origin"]
    if kw.get("auth"):    rh["Authorization"] = kw["auth"]
    for k, v in (kw.get("req_headers") or {}).items():
        rh[k] = v
    sh = {"Content-Type": kw.get("ct", "text/html")}
    sh.update(kw.get("resp_headers") or {})
    return Transaction(method, url, status=kw.get("status", 200), resp_headers=sh,
                       resp_body=kw.get("body", ""), req_headers=rh, req_body=kw.get("req_body", ""))


# benign noise present in every capture — must never become the top lead.
# Includes look-alike FALSE-POSITIVE TRAPS: the tool must not flag these.
NOISE = [
    T_("GET", f"{L}/academyLabHeader", status=101, resp_headers={"Upgrade": "websocket"}),  # lab chrome
    T_("GET", f"{L}/resources/css/labsBlog.css", ct="text/css", body="body{}"),
    T_("GET", f"{L}/resources/labheader/js/labHeader.js", ct="application/javascript",
       body="var x=location.search; el.innerHTML=x;"),   # chrome DOM sink — must be ignored
    T_("GET", f"{L}/favicon.ico", ct="image/x-icon"),
    T_("GET", f"{L}/home", body="<h1>Welcome to the shop</h1>"),
    # --- false-positive traps ---
    T_("GET", f"{L}/?search=12345", body="<h1>0 results for 12345</h1>"),           # numeric reflection, not XSS
    T_("GET", f"{L}/search_res?q=x", ct="application/json",
       body='{"results":[{"id":5,"title":"t"},{"id":6,"title":"u"}]}'),             # blog ids, not IDOR
    T_("GET", f"{L}/", cookie="session=dGhpcy1pcy1ub3QtYS1qd3Q; prefs=dark"),        # base64 cookie, not a JWT
    T_("POST", f"{L}/newsletter/subscribe", req_ct="application/x-www-form-urlencoded",
       req_body="email=a@b.com&csrf=TOKEN123"),                                      # CSRF token present
    T_("GET", f"{L}/public-data", origin="https://evil.example", ct="application/json",
       resp_headers={"Access-Control-Allow-Origin": "*"}, body='{"public":true}'),   # ACAO:* no creds
    T_("POST", f"{L}/submit", req_ct="application/x-www-form-urlencoded", req_body="data=1"),  # CL-only, no smuggle
]

# (name, stage, intended_class, [vuln txns])
CASES = [
    # ---------------- STAGE 1 — FOOTHOLD ----------------
    ("content-discovery (.git leak)", Stage.FOOTHOLD, "content-discovery",
     [T_("GET", f"{L}/.git/config", ct="text/plain", body="[core] repositoryformatversion=0 url=creds")]),
    ("DOM XSS (location->innerHTML)", Stage.FOOTHOLD, "dom-xss",
     [T_("GET", f"{L}/js/app.js", ct="application/javascript",
         body="var q=location.search; document.getElementById('x').innerHTML=q;")]),
    ("web-message XSS (no origin check)", Stage.FOOTHOLD, "web-message-xss",
     [T_("GET", f"{L}/channel", body="window.addEventListener('message',function(e){document.body.innerHTML=e.data;});")]),
    ("reflected XSS (search)", Stage.FOOTHOLD, "reflected-stored-xss",
     [T_("GET", f"{L}/?search=hackme", body="<h1>0 results for hackme</h1>")]),
    ("cache poisoning (unkeyed header)", Stage.FOOTHOLD, "cache-poisoning",
     [T_("GET", f"{L}/js/tracking.js", ct="application/javascript",
         resp_headers={"X-Cache": "hit", "Age": "31"}, body="data=1")]),
    ("host-header (reset poison)", Stage.FOOTHOLD, "host-header",
     [T_("POST", f"{L}/forgot-password", host="0aXXlab.web-security-academy.net",
         req_ct="application/x-www-form-urlencoded", req_body="username=carlos",
         body="A reset link was sent to https://0aXXlab.web-security-academy.net/reset?token=abc")]),
    ("request smuggling (TE+CL)", Stage.FOOTHOLD, "request-smuggling",
     [T_("POST", f"{L}/", req_headers={"Transfer-Encoding": "chunked", "Content-Length": "6"},
         req_body="0\r\n\r\nG")]),
    ("user enumeration (login)", Stage.FOOTHOLD, "user-enum-brute",
     [T_("POST", f"{L}/login", req_ct="application/x-www-form-urlencoded",
         req_body="username=carlos&password=x", body="Invalid username")]),
    ("OAuth (no state)", Stage.FOOTHOLD, "oauth-takeover",
     [T_("GET", f"{L}/auth?client_id=abc&redirect_uri=https://cb&response_type=token&scope=openid",
         status=302)]),
    ("CSWSH (cookie-auth socket)", Stage.FOOTHOLD, "cswsh",
     [T_("GET", f"{L}/chat", status=101, resp_headers={"Upgrade": "websocket"})]),

    # ---------------- STAGE 2 — PRIVESC ----------------
    ("SQLi (error-based filter)", Stage.PRIVESC, "sql-injection",
     [T_("GET", f"{L}/filter?category=Gifts'", status=500,
         body="You have an error in your SQL syntax; SQLSTATE[42000]")]),
    ("mass assignment (roleid leak)", Stage.PRIVESC, "idor-mass-assign",
     [T_("POST", f"{L}/my-account/change-email", req_ct="application/json",
         req_body='{"email":"x@x.com"}', ct="application/json",
         body='{"username":"wiener","email":"x@x.com","roleid":7}')]),
    ("method-based access control", Stage.PRIVESC, "idor-mass-assign",
     [T_("POST", f"{L}/admin-roles", status=401, req_ct="application/x-www-form-urlencoded",
         req_body="username=carlos&action=upgrade", body="Unauthorized")]),
    ("CSRF (no token)", Stage.PRIVESC, "csrf-takeover",
     [T_("POST", f"{L}/my-account/change-email", req_ct="application/x-www-form-urlencoded",
         req_body="email=attacker@evil.com")]),
    ("password reset logic", Stage.PRIVESC, "password-reset-logic",
     [T_("POST", f"{L}/forgot-password?temp-forgot-password-token=abc123",
         req_ct="application/x-www-form-urlencoded",
         req_body="temp-forgot-password-token=abc123&new-password-1=x&new-password-2=x")]),
    ("JWT (alg:none)", Stage.PRIVESC, "jwt-forge",
     [T_("GET", f"{L}/my-account", cookie="session=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ3aWVuZXIifQ.")]),
    ("JWT (algorithm confusion RS256)", Stage.PRIVESC, "jwt-forge",
     [T_("GET", f"{L}/my-account", cookie="session=eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiJ3aWVuZXIifQ.sig")]),
    ("CORS (reflect origin + creds)", Stage.PRIVESC, "cors-exfil",
     [T_("GET", f"{L}/accountDetails", origin="https://evil.example", ct="application/json",
         resp_headers={"Access-Control-Allow-Origin": "https://evil.example",
                       "Access-Control-Allow-Credentials": "true"}, body='{"apikey":"K"}')]),
    ("API / GraphQL", Stage.PRIVESC, "api-graphql",
     [T_("POST", f"{L}/graphql/v1", req_ct="application/json",
         req_body='{"query":"{__schema{types{name}}}"}')]),
    ("client-side prototype pollution", Stage.PRIVESC, "client-side-proto-pollution",
     [T_("GET", f"{L}/?__proto__[transport_url]=data:,alert(1)")]),

    # ---------------- STAGE 3 — EXFIL ----------------
    ("OS command injection (ImgSize)", Stage.EXFIL, "os-command-injection",
     [T_("GET", f"{L}/admin/image?imageFileName=1.jpg&ImgSize=120", ct="image/jpeg")]),
    ("path traversal (file param)", Stage.EXFIL, "path-traversal",
     [T_("GET", f"{L}/image?filename=photo.jpg", ct="image/jpeg")]),
    ("SSTI (template preview)", Stage.EXFIL, "ssti",
     [T_("GET", f"{L}/email-template-preview?message=hi")]),
    ("XXE (xml body)", Stage.EXFIL, "xxe",
     [T_("POST", f"{L}/stock", req_ct="application/xml",
         req_body="<?xml version='1.0'?><stockCheck><productId>1</productId></stockCheck>")]),
    ("SSRF (url fetcher)", Stage.EXFIL, "ssrf",
     [T_("POST", f"{L}/product/stock", req_ct="application/x-www-form-urlencoded",
         req_body="stockApi=http://stock.internal:8080/")]),
    ("file upload -> RCE", Stage.EXFIL, "file-upload-rce",
     [T_("POST", f"{L}/my-account/avatar", req_ct="multipart/form-data; boundary=xy",
         req_body="--xy filename=avatar.php Content-Type: image/jpeg")]),
    ("insecure deserialization", Stage.EXFIL, "deserialization",
     [T_("GET", f"{L}/my-account", cookie="session=rO0ABXNyABFqYXZhLnV0aWwu")]),
    ("server-side prototype pollution", Stage.EXFIL, "server-side-proto-pollution",
     [T_("POST", f"{L}/my-account/change-address", req_ct="application/json",
         req_body='{"address_line_1":"x","__proto__":{"isAdmin":true}}')]),

    # ---------------- harder variants (second improve pass) ----------------
    ("host-header: localhost admin bypass", Stage.FOOTHOLD, "host-header",
     [T_("GET", f"{L}/admin", status=401, body="Admin interface only available to local users")]),
    ("cache: parameter cloaking (JSONP)", Stage.FOOTHOLD, "cache-poisoning",
     [T_("GET", f"{L}/js/geolocate.js?callback=setCountryCookie&utm_content=x;callback=alert(1)",
         ct="application/javascript", resp_headers={"X-Cache": "hit", "Age": "9"},
         body="setCountryCookie(1)")]),
    ("OAuth: forced profile linking", Stage.FOOTHOLD, "oauth-takeover",
     [T_("GET", f"{L}/oauth-linking?code=abc123")]),
    ("SQLi: blind via TrackingId cookie", Stage.PRIVESC, "sql-injection",
     [T_("GET", f"{L}/", cookie="TrackingId=u8Gm3; session=abc")]),
    ("path traversal: download path param", Stage.EXFIL, "path-traversal",
     [T_("GET", f"{L}/download?path=brochure.pdf")]),
    ("file upload: Content-Type bypass", Stage.EXFIL, "file-upload-rce",
     [T_("POST", f"{L}/my-account/avatar", req_ct="multipart/form-data; boundary=xy",
         req_body="--xy filename=shell.phtml Content-Type: image/jpeg")]),
]


def check_case(stage, intended, txns):
    cands = triage(stage, NOISE + txns, PH)
    classes = {c.vuln_class for c in cands}
    top = cands[0] if cands else None
    detected = intended in classes
    is_top = bool(top and top.vuln_class == intended)
    has_payload = bool(top and top.payloads)
    has_labs = bool(top and top.labs)
    wi, ns = T.what_is(intended), T.next_step(intended)
    has_guidance = (wi != _GENERIC_WHATIS) and (ns != _GENERIC_NEXT)
    ok = all((detected, is_top, has_payload, has_labs, has_guidance))
    why = []
    if not detected:     why.append("not detected")
    if not is_top:       why.append(f"not #1 (top={top.vuln_class if top else 'none'})")
    if not has_payload:  why.append("no payload")
    if not has_labs:     why.append("no labs")
    if not has_guidance: why.append("no plain guidance")
    return ok, why


def run_matrix():
    print("=" * 70)
    print("  LAYER 1 — COVERAGE MATRIX (guided-pass per vuln class)")
    print("=" * 70)
    passed = 0
    for name, stage, intended, txns in CASES:
        ok, why = check_case(stage, intended, txns)
        passed += ok
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] S{int(stage)} {name:38} -> {intended}"
        if not ok:
            line += f"   >>> {', '.join(why)}"
        print(line)
    rate = 100.0 * passed / len(CASES)
    print(f"\n  matrix guided-pass: {passed}/{len(CASES)}  =  {rate:.1f}%")
    return passed, len(CASES)


# ---------------- LAYER 2: full-chain apps ----------------
def app_a():
    return [
        T_("GET", f"{L}/.git/config", ct="text/plain", body="[core] url=creds"),
        T_("GET", f"{L}/filter?category=Gifts'", status=500, body="error in your SQL syntax SQLSTATE"),
        T_("GET", f"{L}/email-template-preview?message=hi"),
    ]


def app_b():
    return [
        T_("GET", f"{L}/auth?client_id=a&redirect_uri=https://cb&response_type=token&scope=openid", status=302),
        T_("GET", f"{L}/my-account", cookie="session=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ3aWVuZXIifQ."),
        T_("GET", f"{L}/admin/image?imageFileName=1.jpg&ImgSize=120", ct="image/jpeg"),
    ]


APPS = [
    ("App A", app_a, {Stage.FOOTHOLD: "content-discovery", Stage.PRIVESC: "sql-injection", Stage.EXFIL: "ssti"}),
    ("App B", app_b, {Stage.FOOTHOLD: "oauth-takeover", Stage.PRIVESC: "jwt-forge", Stage.EXFIL: "os-command-injection"}),
]


def run_apps():
    print("\n" + "=" * 70)
    print("  LAYER 2 — FULL-CHAIN APPS (both must pass, like the real exam)")
    print("=" * 70)
    cfg = Config(lab="0aXXlab.web-security-academy.net", exploit="ex.exploit-server.net",
                 collab="c.oastify.com", proxy=None, mode="lab")
    cfg.scope = ["0aXXlab.web-security-academy.net"]
    all_ok = True
    for name, fn, intended in APPS:
        orch = Orchestrator(cfg, gate_fn=lambda s, n: True)
        orch.session.sess = None
        with contextlib.redirect_stdout(io.StringIO()):   # mute the engine board
            res = orch.run(fn(), auto_proceed=True)
        app_ok = True
        for stage, want in intended.items():
            ranked = res[stage].ranked() if stage in res else []
            top = ranked[0] if ranked else None
            ok = bool(top and top.vuln_class == want and top.payloads and top.labs
                      and T.next_step(want) != _GENERIC_NEXT)
            app_ok = app_ok and ok
        all_ok = all_ok and app_ok
        print(f"  [{'PASS' if app_ok else 'FAIL'}] {name}")
    print(f"\n  exam result: {'PASS ✅' if all_ok else 'FAIL ❌'}")
    return all_ok


# ---------------- LAYER 3: contested stages (ranking robustness) ----------------
# Several REAL bugs in one stage — the agent must lead with the highest-value one.
CONTESTED = [
    ("PRIVESC: SQLi beats roleid-leak", Stage.PRIVESC, "sql-injection", [
        T_("GET", f"{L}/filter?category=Gifts'", status=500, body="error in your SQL syntax SQLSTATE"),
        T_("POST", f"{L}/my-account/change-email", req_ct="application/json", ct="application/json",
           req_body='{"email":"x"}', body='{"username":"wiener","roleid":7}'),
    ]),
    ("PRIVESC: JWT beats CORS", Stage.PRIVESC, "jwt-forge", [
        T_("GET", f"{L}/my-account", cookie="session=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ3aWVuZXIifQ."),
        T_("GET", f"{L}/accountDetails", origin="https://evil.example", ct="application/json",
           resp_headers={"Access-Control-Allow-Origin": "https://evil.example",
                         "Access-Control-Allow-Credentials": "true"}, body='{"apikey":"K"}'),
    ]),
    ("EXFIL: cmdi beats ssrf+traversal", Stage.EXFIL, "os-command-injection", [
        T_("GET", f"{L}/admin/image?imageFileName=1.jpg&ImgSize=120", ct="image/jpeg"),
        T_("POST", f"{L}/product/stock", req_ct="application/x-www-form-urlencoded",
           req_body="stockApi=http://internal/"),
        T_("GET", f"{L}/download?path=brochure.pdf"),
    ]),
    ("FOOTHOLD: .git beats reflected-xss", Stage.FOOTHOLD, "content-discovery", [
        T_("GET", f"{L}/.git/config", ct="text/plain", body="[core] url=creds"),
        T_("GET", f"{L}/?search=hackme", body="<h1>0 results for hackme</h1>"),
    ]),
    ("EXFIL: deserialization beats path-traversal", Stage.EXFIL, "deserialization", [
        T_("GET", f"{L}/my-account", cookie="session=rO0ABXNyABFqYXZhLnV0aWwu"),
        T_("GET", f"{L}/image?filename=x.jpg", ct="image/jpeg"),
    ]),
]


def run_contested():
    print("\n" + "=" * 70)
    print("  LAYER 3 — CONTESTED STAGES (agent leads with the highest-value bug)")
    print("=" * 70)
    passed = 0
    for name, stage, want, txns in CONTESTED:
        cands = triage(stage, NOISE + txns, PH)
        top = cands[0] if cands else None
        # the intended must be #1 AND at least 2 real candidates must compete
        ok = bool(top and top.vuln_class == want and len(cands) >= 2 and top.payloads
                  and T.next_step(want) != _GENERIC_NEXT)
        passed += ok
        comp = ", ".join(f"{c.title}({c.score})" for c in cands[:3])
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:42} top={top.vuln_class if top else '-'}  | {comp}")
    rate = 100.0 * passed / len(CONTESTED)
    print(f"\n  contested-stage lead accuracy: {passed}/{len(CONTESTED)} = {rate:.1f}%")
    return passed, len(CONTESTED)


def main():
    p, n = run_matrix()
    cp, cn = run_contested()
    apps_ok = run_apps()
    p, n = p + cp, n + cn
    rate = 100.0 * p / n
    print("\n" + "=" * 70)
    ok = (rate >= 99.0) and apps_ok
    print(f"  OVERALL: matrix {rate:.1f}%  ·  apps {'PASS' if apps_ok else 'FAIL'}  ·  "
          f"{'✅ TARGET MET (>=99%)' if ok else '❌ below target'}")
    print("=" * 70)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
