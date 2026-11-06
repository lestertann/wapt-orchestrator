"""Benchmark catalog modeled on the PortSwigger Web Security Academy labs.

Each entry reproduces the SIGNAL a lab exposes, so the tool is scored on whether
it (a) detects the right vuln class and (b) actively confirms the real ones /
rejects benign ones. Names match real labs so gap_report.md reads like a lab
checklist. Extend freely — every scenario you add is a target the auto-improve
loop will work to pass.

detection scenario  = a crafted request/response carrying the signal (no network)
confirm scenario    = a live mock server (labmocks) the active probe is run against
"""
from __future__ import annotations

from wapt.models import Stage, Transaction
import labmocks as M

F, P, E = Stage.FOOTHOLD, Stage.PRIVESC, Stage.EXFIL


class Scenario:
    def __init__(self, name, topic, stage, vuln_class, kind, *, txn=None,
                 handler=None, spec=None, expect_detect=True, expect_confirm=None,
                 param=None, benign=False):
        self.name, self.topic, self.stage = name, topic, stage
        self.vuln_class, self.kind = vuln_class, kind
        self.txn, self.handler, self.spec = txn, handler, spec
        self.expect_detect, self.expect_confirm = expect_detect, expect_confirm
        self.param, self.benign = param, benign


def D(name, topic, cls, stage, *, url, body="", ct="text/html", status=200,
      method="GET", cookie=None, req_ct=None, req_body="", host=None, origin=None,
      resp_headers=None, expect_detect=True, benign=False):
    """A detection scenario built from a crafted transaction. Set benign=True +
    expect_detect=False to make a FALSE-POSITIVE TRAP the tool must NOT flag."""
    rh = {}
    if cookie: rh["Cookie"] = cookie
    if req_ct: rh["Content-Type"] = req_ct
    if host: rh["Host"] = host
    if origin: rh["Origin"] = origin
    sh = {"Content-Type": ct}
    if resp_headers: sh.update(resp_headers)
    txn = Transaction(method, url, status=status, resp_headers=sh, resp_body=body,
                      req_headers=rh, req_body=req_body)
    return Scenario(name, topic, stage, cls, "detect", txn=txn,
                    expect_detect=expect_detect, benign=benign)


def C(name, topic, cls, stage, handler, url, *, param, expect_confirm=True,
      ct="application/json", cookie=None, benign=False, expect_context=None, origin=None):
    spec = {"url": url, "ct": ct, "cookie": cookie, "method": "GET", "body": None,
            "origin": origin}
    sc = Scenario(name, topic, stage, cls, "confirm", handler=handler, spec=spec,
                  param=param, expect_confirm=expect_confirm, benign=benign)
    sc.expect_context = expect_context   # substring the confirm verdict must contain
    return sc


LAB = "https://0aXXlab.web-security-academy.net"

CATALOG: list[Scenario] = [

    # ---- Information disclosure / content discovery ----
    D("Information disclosure in error messages", "info-disclosure", "content-discovery", F,
      url=f"{LAB}/product?productId=x", status=500,
      body="java.lang.NumberFormatException Traceback (most recent call last): at org.apache..."),
    D("Source code disclosure via backup files", "info-disclosure", "content-discovery", F,
      url=f"{LAB}/backup/ProductTemplate.java.bak", body="public class ProductTemplate {"),
    D("Information disclosure in version control history", "info-disclosure", "content-discovery", F,
      url=f"{LAB}/.git/config", body="[core] repositoryformatversion = 0"),

    # ---- Cross-site scripting ----
    C("Reflected XSS into HTML context with nothing encoded", "xss", "reflected-stored-xss", F,
      M.XssHtml, f"{LAB}/search?search=gift", param="search"),
    C("Reflected XSS into attribute with angle brackets HTML-encoded", "xss", "reflected-stored-xss", F,
      M.XssAttribute, f"{LAB}/search?search=gift", param="search"),
    C("Reflected DOM XSS (eval on JSON response)", "xss", "reflected-stored-xss", F,
      M.XssEvalSink, f"{LAB}/search_res?SearchTerm=gift", param="SearchTerm"),
    C("Reflected XSS into a JavaScript string", "xss", "reflected-stored-xss", F,
      M.XssJsString, f"{LAB}/search?search=gift", param="search", ct="text/html",
      expect_context="javascript"),
    C("Reflected XSS into HTML comment", "xss", "reflected-stored-xss", F,
      M.XssComment, f"{LAB}/search?search=gift", param="search", ct="text/html",
      expect_context="comment"),
    C("Benign search — safely HTML-encoded (must NOT confirm)", "xss", "reflected-stored-xss", F,
      M.BenignEscaped, f"{LAB}/search?search=gift", param="search",
      expect_confirm=False, benign=True),
    D("DOM XSS in innerHTML sink using source location.search", "xss", "dom-xss", F,
      url=f"{LAB}/resources/js/searchResults.js", ct="application/javascript",
      body="var q=new URLSearchParams(location.search).get('q'); el.innerHTML = q;"),
    D("DOM XSS using web messages", "xss", "web-message-xss", F,
      url=f"{LAB}/", body="window.addEventListener('message', function(e){ document.body.innerHTML = e.data; });"),
    D("Stored XSS into HTML context with nothing encoded", "xss", "reflected-stored-xss", F,
      url=f"{LAB}/post/comment?postId=3&comment=nicepost&name=bob", method="POST",
      body="<p>nicepost</p>"),

    # ---- SQL injection ----
    C("SQL injection UNION attack, retrieving data (error-based)", "sqli", "sql-injection", P,
      M.SqliError, f"{LAB}/search_res?SearchTerm=gift", param="SearchTerm", cookie="TrackingId=abc"),
    C("Blind SQL injection with conditional responses", "sqli", "sql-injection", P,
      M.SqliBoolean, f"{LAB}/filter?q=gift&category=x", param="q", ct="text/html",
      cookie="TrackingId=abc"),
    C("Blind SQL injection with time delays", "sqli", "sql-injection", P,
      M.SqliTime, f"{LAB}/filter?category=Gifts&q=x", param="q", ct="text/html",
      cookie="TrackingId=abc", expect_context="time-based"),
    C("Benign: uniformly slow filter, not injectable (must NOT confirm SQLi)",
      "sqli", "sql-injection", P, M.SqliSlowBenign, f"{LAB}/filter?category=Gifts&q=x",
      param="q", ct="text/html", cookie="TrackingId=abc", expect_confirm=False, benign=True),
    D("SQL injection in WHERE clause (category filter)", "sqli", "sql-injection", P,
      url=f"{LAB}/filter?category=Gifts"),
    D("SQL injection via TrackingId cookie", "sqli", "sql-injection", P,
      url=f"{LAB}/", cookie="TrackingId=xyz123; session=abc"),

    # ---- Authentication ----
    D("Username enumeration via different responses", "auth", "user-enum-brute", F,
      url=f"{LAB}/login", method="POST", req_ct="application/x-www-form-urlencoded",
      req_body="username=carlos&password=x", body="Invalid username"),
    D("2FA broken logic", "auth", "user-enum-brute", F,
      url=f"{LAB}/login2", method="POST", req_body="mfa-code=1234"),

    # ---- Access control / IDOR / mass assignment ----
    D("User role can be modified in user profile", "access-control", "idor-mass-assign", P,
      url=f"{LAB}/my-account/change-email", method="POST", ct="application/json",
      body='{"username":"wiener","email":"x@x.com","roleid":5}'),
    D("User ID controlled by request parameter with password disclosure", "access-control", "idor-mass-assign", P,
      url=f"{LAB}/my-account?id=carlos", ct="application/json",
      body='{"username":"carlos","id":1234,"email":"c@x.com"}'),

    # ---- CSRF ----
    D("CSRF vulnerability with no defenses", "csrf", "csrf-takeover", P,
      url=f"{LAB}/my-account/change-email", method="POST",
      req_ct="application/x-www-form-urlencoded", req_body="email=attacker@evil.com"),
    D("CSRF where token is not tied to user session", "csrf", "csrf-takeover", P,
      url=f"{LAB}/my-account/change-email", method="POST",
      req_ct="application/x-www-form-urlencoded",
      req_body="email=attacker@evil.com&csrf=abc123"),

    # ---- CORS ----
    D("CORS vulnerability with basic origin reflection", "cors", "cors-exfil", P,
      url=f"{LAB}/accountDetails", origin="https://evil.example",
      resp_headers={"Access-Control-Allow-Origin": "https://evil.example",
                    "Access-Control-Allow-Credentials": "true"},
      body='{"apikey":"SECRET"}', ct="application/json"),

    C("CORS reflects arbitrary origin with credentials", "cors", "cors-exfil", P,
      M.CorsReflect, f"{LAB}/accountDetails", param="origin", ct="application/json",
      origin="https://0aXXlab.web-security-academy.net", expect_context="arbitrary origin"),
    C("Benign CORS — strict allow-list, attacker origin rejected (must NOT confirm)",
      "cors", "cors-exfil", P, M.CorsTrustedOnly, f"{LAB}/accountDetails", param="origin",
      ct="application/json", origin="https://0aXXlab.web-security-academy.net",
      expect_confirm=False, benign=True),
    C("CORS trusts only Origin: null (sandboxed-iframe exploit)", "cors", "cors-exfil", P,
      M.CorsNullOnly, f"{LAB}/accountDetails", param="origin", ct="application/json",
      origin="null", expect_context="null"),

    # ---- JWT ----
    D("JWT authentication bypass via unverified signature", "jwt", "jwt-forge", P,
      url=f"{LAB}/my-account",
      cookie="session=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ3aWVuZXIifQ.c2ln"),

    # ---- OAuth ----
    D("Authentication bypass via OAuth implicit flow", "oauth", "oauth-takeover", F,
      url=f"{LAB}/auth?client_id=abc&redirect_uri=https://cb&response_type=token&scope=openid"),

    # ---- WebSockets ----
    D("Cross-site WebSocket hijacking", "websockets", "cswsh", F,
      url=f"{LAB}/chat", status=101, body="",
      resp_headers={"Upgrade": "websocket"}),

    # ---- Web cache poisoning ----
    D("Web cache poisoning with an unkeyed header", "cache", "cache-poisoning", F,
      url=f"{LAB}/resources/js/tracking.js", ct="application/javascript",
      resp_headers={"X-Cache": "hit", "Age": "33"}, body="data=1"),

    # ---- HTTP request smuggling ----
    D("HTTP request smuggling, basic CL.TE vulnerability", "smuggling", "request-smuggling", F,
      url=f"{LAB}/", method="POST",
      req_body="0\r\n\r\nG", status=200),  # TE+CL set below via headers trick

    # ---- Host header ----
    D("Basic password reset poisoning", "host-header", "host-header", F,
      url=f"{LAB}/forgot-password", method="POST", host="0aXXlab.web-security-academy.net",
      body="A reset link was sent to https://0aXXlab.web-security-academy.net/reset?token=abc"),

    # ---- Prototype pollution ----
    D("DOM XSS via client-side prototype pollution", "proto-pollution", "client-side-proto-pollution", P,
      url=f"{LAB}/?__proto__[transport_url]=data:,alert(1)"),
    D("Remote code execution via server-side prototype pollution", "proto-pollution", "server-side-proto-pollution", E,
      url=f"{LAB}/my-account/change-address", method="POST", req_ct="application/json",
      req_body='{"address":"x","__proto__":{"isAdmin":true}}'),

    # ---- API / GraphQL ----
    D("Finding a hidden GraphQL endpoint", "api", "api-graphql", P,
      url=f"{LAB}/graphql/v1", method="POST", req_ct="application/json",
      req_body='{"query":"{__schema{types{name}}}"}'),

    # ---- Path traversal (EXFIL) ----
    C("File path traversal, simple case", "traversal", "path-traversal", E,
      M.Traversal, f"{LAB}/image?filename=image1.jpg", param="filename", ct="image/jpeg"),
    D("Traversal sequences stripped with superfluous URL-decode", "traversal", "path-traversal", E,
      url=f"{LAB}/image?filename=photo.png"),

    # ---- OS command injection (EXFIL) ----
    D("OS command injection, simple case (feedback)", "cmdi", "os-command-injection", E,
      url=f"{LAB}/feedback/submit", method="POST", req_ct="application/x-www-form-urlencoded",
      req_body="email=test@x.com&message=hi&name=bob"),
    D("Blind OS command injection via image size param", "cmdi", "os-command-injection", E,
      url=f"{LAB}/admin_panel/adminimage?imageFileName=66.jpg&ImgSize=200x200"),
    C("Blind cmdi confirmed by response delay (time-based)", "cmdi", "os-command-injection", E,
      M.CmdiTime, f"{LAB}/admin_panel/adminimage?imageFileName=66.jpg&ImgSize=3x3",
      param="imageFileName", ct="text/html", expect_context="time-based"),
    C("Benign: uniformly slow image endpoint (not injectable — must NOT confirm)",
      "cmdi", "os-command-injection", E, M.CmdiSlowBenign,
      f"{LAB}/admin_panel/adminimage?imageFileName=66.jpg&ImgSize=3x3",
      param="imageFileName", ct="text/html", expect_confirm=False, benign=True),

    # ---- SSRF (EXFIL) ----
    C("Basic SSRF against another back-end system", "ssrf", "ssrf", E,
      M.Ssrf, f"{LAB}/product/stock?url=http://stock.weliketoshop.net/", param="url", ct="text/html"),
    D("SSRF via stockApi POST body", "ssrf", "ssrf", E,
      url=f"{LAB}/product/stock", method="POST", req_ct="application/x-www-form-urlencoded",
      req_body="stockApi=http://stock.weliketoshop.net:8080/product?productId=1"),
    D("Blind SSRF with out-of-band detection (report generator)", "ssrf", "ssrf", E,
      url=f"{LAB}/admin/generate-report", method="POST", req_ct="application/json",
      req_body='{"PageHtml":"<p>report</p>","url":"https://x/"}'),

    # ---- XXE (EXFIL) ----
    D("Exploiting XXE using external entities to retrieve files", "xxe", "xxe", E,
      url=f"{LAB}/product/stock", method="POST", req_ct="application/xml",
      req_body="<?xml version='1.0'?><stockCheck><productId>1</productId></stockCheck>"),

    # ---- SSTI (EXFIL) ----
    D("Basic server-side template injection", "ssti", "ssti", E,
      url=f"{LAB}/email-template-preview?message=hi"),
    C("SSTI — arithmetic confirms the engine (Jinja/Twig)", "ssti", "ssti", E,
      M.Ssti, f"{LAB}/email-template-preview?message=hi", param="message",
      ct="text/html", expect_context="jinja"),
    C("Benign reflection — looks templatey but 7*7 stays literal (must NOT confirm)",
      "ssti", "ssti", E, M.BenignTemplate, f"{LAB}/email-template-preview?message=hi",
      param="message", ct="text/html", expect_confirm=False, benign=True),
    C("SSTI — ERB engine (only <%=…%> evaluates)", "ssti", "ssti", E,
      M.SstiErb, f"{LAB}/email-template-preview?message=hi", param="message",
      ct="text/html", expect_context="erb"),

    # ---- File upload (EXFIL) ----
    D("Remote code execution via web shell upload", "upload", "file-upload-rce", E,
      url=f"{LAB}/my-account/avatar", method="POST",
      req_ct="multipart/form-data; boundary=xyz", req_body="--xyz filename=avatar.png"),

    # ---- Deserialization (EXFIL) ----
    D("Modifying serialized objects (PHP)", "deserialization", "deserialization", E,
      url=f"{LAB}/my-account",
      cookie='session=O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}'),
    D("Exploiting Java deserialization with Apache Commons", "deserialization", "deserialization", E,
      url=f"{LAB}/my-account", cookie="session=rO0ABXNyABFqYXZhLnV0aWwu"),

    # ---- more coverage (second pass) ----
    D("DOM XSS in document.write sink using location.search", "xss", "dom-xss", F,
      url=f"{LAB}/resources/js/trackSearch.js", ct="application/javascript",
      body="document.write('<img src=\"/res?'+location.search.slice(1)+'\">');"),
    D("Visible error-based SQL injection", "sqli", "sql-injection", P,
      url=f"{LAB}/product?productId=1'", ct="text/html",
      body="Unterminated string literal. SQLSTATE[42000] You have an error in your SQL syntax"),
    D("Password reset broken logic", "auth", "password-reset-logic", P,
      url=f"{LAB}/forgot-password?temp-forgot-password-token=abc123", method="POST",
      req_ct="application/x-www-form-urlencoded",
      req_body="temp-forgot-password-token=abc123&new-password-1=hacked&new-password-2=hacked"),
    D("SSRF with blacklist-based input filter", "ssrf", "ssrf", E,
      url=f"{LAB}/product/stock", method="POST", req_ct="application/x-www-form-urlencoded",
      req_body="stockApi=http://127.1/admin"),
    D("Web shell upload via Content-Type restriction bypass", "upload", "file-upload-rce", E,
      url=f"{LAB}/my-account/avatar", method="POST",
      req_ct="multipart/form-data; boundary=xy", req_body="--xy filename=shell.php Content-Type: image/jpeg"),
    D("JWT authentication bypass via jwk header injection", "jwt", "jwt-forge", P,
      url=f"{LAB}/admin",
      cookie="session=eyJraWQiOiIxIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ3aWVuZXIifQ.sig"),
    D("Accessing private GraphQL posts", "api", "api-graphql", P,
      url=f"{LAB}/graphql/v1", method="POST", req_ct="application/json",
      req_body='{"query":"query{getBlogPost(id:3){postPassword}}"}'),
    D("Privilege escalation via server-side prototype pollution", "proto-pollution",
      "server-side-proto-pollution", E,
      url=f"{LAB}/my-account/change-address", method="POST", req_ct="application/json",
      req_body='{"address_line_1":"x","__proto__":{"isAdmin":true}}'),
    D("Information disclosure on debug page", "info-disclosure", "content-discovery", F,
      url=f"{LAB}/cgi-bin/phpinfo.php", body="phpinfo() PHP Version 7.4 SECRET_KEY=..."),

    # ======================= third pass: harder TPs =======================
    D("Stored XSS into HTML context (comment shown)", "xss", "reflected-stored-xss", F,
      url=f"{LAB}/post?postId=3&comment=HACKER123", body="<p>HACKER123</p> great post"),
    D("SSRF via imageUrl parameter", "ssrf", "ssrf", E,
      url=f"{LAB}/product?imageUrl=https://cdn.example/1.png"),
    D("Path traversal via 'path' parameter", "traversal", "path-traversal", E,
      url=f"{LAB}/download?path=brochure.pdf"),
    D("Reflected XSS in search (query param)", "xss", "reflected-stored-xss", F,
      url=f"{LAB}/?query=widget", body="<h2>Results for widget</h2>"),
    D("CORS trusted null origin", "cors", "cors-exfil", P,
      url=f"{LAB}/accountDetails", origin="null",
      resp_headers={"Access-Control-Allow-Origin": "null",
                    "Access-Control-Allow-Credentials": "true"},
      body='{"apikey":"K"}', ct="application/json"),

    # ======================= false-positive traps (must NOT flag) =======================
    D("Benign: numeric search reflected (no XSS)", "xss", "reflected-stored-xss", F,
      url=f"{LAB}/?search=12345", body="<h1>0 results for 12345</h1>",
      expect_detect=False, benign=True),
    D("Benign: blog post ids in listing (no IDOR)", "access-control", "idor-mass-assign", P,
      url=f"{LAB}/search_res?q=x", ct="application/json",
      body='{"results":[{"id":5,"title":"t"},{"id":6,"title":"u"}]}',
      expect_detect=False, benign=True),
    D("Benign: random base64 cookie (not a JWT)", "jwt", "jwt-forge", P,
      url=f"{LAB}/", cookie="session=dGhpcy1pcy1ub3QtYS1qd3Q; prefs=dark",
      expect_detect=False, benign=True),
    D("Benign: normal POST with CSRF token present", "csrf", "csrf-takeover", P,
      url=f"{LAB}/newsletter/subscribe", method="POST",
      req_ct="application/x-www-form-urlencoded",
      req_body="email=a@b.com&csrf=TOKEN123", expect_detect=False, benign=True),
    D("Benign: only Content-Length, no TE (no smuggling)", "smuggling", "request-smuggling", F,
      url=f"{LAB}/submit", method="POST", req_body="data=1", expect_detect=False, benign=True),
    D("Benign: CORS wildcard ACAO:* with no credentials (not exploitable)", "cors", "cors-exfil", P,
      url=f"{LAB}/public-data", origin="https://evil.example",
      resp_headers={"Access-Control-Allow-Origin": "*"},
      body='{"public":true}', ct="application/json", expect_detect=False, benign=True),

    # ======================= more true-positive coverage =======================
    D("SSTI via 'out of stock' message reflecting input", "ssti", "ssti", E,
      url=f"{LAB}/product?productId=1", body="<p>Sorry, this product is out of stock</p>"),

    # ===== fourth pass: Stage-2 variants drilled in the BSCP grind =====
    # JWT — the header now names the specific attack (alg:none / confusion / kid / jwk)
    D("JWT authentication bypass via algorithm confusion", "jwt", "jwt-forge", P,
      url=f"{LAB}/my-account",
      cookie="session=eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiJ3aWVuZXIifQ.sig"),
    D("JWT authentication bypass via kid header path traversal", "jwt", "jwt-forge", P,
      url=f"{LAB}/my-account",
      cookie="session=eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uLy4uLy4uLy4uL2Rldi9udWxsIn0.eyJzdWIiOiJ3aWVuZXIifQ.sig"),
    D("JWT authentication bypass via unverified signature (alg:none)", "jwt", "jwt-forge", P,
      url=f"{LAB}/my-account",
      cookie="session=eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIn0."),
    # Access control — method-based circumvention (no detector before this pass)
    D("Method-based access control can be circumvented", "access-control", "idor-mass-assign", P,
      url=f"{LAB}/admin-roles", method="POST", status=401,
      req_ct="application/x-www-form-urlencoded", req_body="username=carlos&action=upgrade"),
    # Web cache poisoning — unkeyed query param / parameter cloaking
    D("Web cache poisoning via an unkeyed query parameter", "cache", "cache-poisoning", F,
      url=f"{LAB}/js/geolocate.js?callback=setCountryCookie&utm_content=x;callback=alert(1)",
      ct="application/javascript", resp_headers={"X-Cache": "hit", "Age": "18"},
      body="setCountryCookie(1)"),
    # WebSocket message manipulation (second WS lab)
    D("Manipulating WebSocket messages to exploit vulnerabilities", "websockets", "cswsh", F,
      url=f"{LAB}/chat", status=101, body="", resp_headers={"Upgrade": "websocket"}),
    # OAuth — forced profile linking (no state on the linking callback)
    D("Forced OAuth profile linking", "oauth", "oauth-takeover", F,
      url=f"{LAB}/oauth-linking?code=abc123"),

    # Host header — localhost admin bypass + routing-based SSRF surface
    D("Host header authentication bypass (localhost)", "host-header", "host-header", F,
      url=f"{LAB}/admin", status=401, body="Admin interface only available to local users"),
    D("Routing-based SSRF via Host header (internal address)", "host-header", "host-header", F,
      url=f"{LAB}/", host="192.168.0.1", body="ok"),

    # ---- false-positive guards for the new passes ----
    D("Benign: admin page loads fine for a real admin (200, no bypass)", "access-control",
      "idor-mass-assign", P, url=f"{LAB}/admin-roles", method="POST", status=200,
      req_ct="application/x-www-form-urlencoded", req_body="username=carlos&action=upgrade",
      expect_detect=False, benign=True),
    D("Benign: normal admin page for a real admin (no local-only hint)", "host-header",
      "host-header", F, url=f"{LAB}/admin", status=200, body="<h1>Admin panel</h1>",
      expect_detect=False, benign=True),
]


# a couple of detection scenarios need raw header shapes the D() helper can't set
def _patch():
    # the real smuggling scenarios need both TE and CL headers; benign traps must
    # NOT get them (they're testing that CL-only traffic is not flagged).
    for sc in CATALOG:
        if sc.vuln_class == "request-smuggling" and sc.txn is not None and not sc.benign:
            sc.txn.req_headers["Transfer-Encoding"] = "chunked"
            sc.txn.req_headers["Content-Length"] = "6"
_patch()
