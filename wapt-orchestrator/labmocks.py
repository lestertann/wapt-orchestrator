"""Self-verifying mock vulnerable servers for the confirmation scenarios.

Only the classes with an active, self-verifying safe probe need a live mock
(SQLi via quote/boolean/UNION, XSS via reflection-context). Out-of-band classes
(SSRF/cmdi/XXE) and logic/forge classes are detection-only in the catalog,
because their confirmation needs Collaborator or human judgment the benchmark
can't stand in for.
"""
import re
import time as _time
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import html as _html


def _send(h, body, ct):
    b = body.encode()
    h.send_response(200); h.send_header("Content-Type", ct)
    h.send_header("Content-Length", str(len(b))); h.end_headers(); h.wfile.write(b)


class SqliError(BaseHTTPRequestHandler):
    """A real UNION-injectable app: quote -> DB error; a 4-column UNION reflects
    its string literals (so column discovery works); a UNION selecting username/
    password dumps the admin creds."""
    def log_message(s, *a): pass
    def do_GET(s):
        t = parse_qs(urlparse(s.path).query, keep_blank_values=True).get("SearchTerm", [""])[0]
        if "UNION SELECT" in t:
            sel = t.split("UNION SELECT", 1)[1].split("--")[0]
            if sel.count(",") + 1 != 4:
                _send(s, '{"error":"The used SELECT statements have a different number of columns"}',
                      "application/json")
            elif "username" in sel and "password" in sel:
                _send(s, '{"results":[{"x":"administrator:s3cr3tpw"}]}', "application/json")
            else:
                lits = " ".join(re.findall(r"'([^']*)'", sel))   # reflect string literals
                _send(s, '{"results":[{"x":"' + lits + '"}]}', "application/json")
        elif t.endswith("'"):
            _send(s, '{"error":"You have an error in your SQL syntax near"}', "application/json")
        else:
            _send(s, '{"results":[1,2,3]}', "application/json")


class SqliBoolean(BaseHTTPRequestHandler):
    """Blind boolean: TRUE looks like baseline, FALSE differs, no error leaked."""
    def log_message(s, *a): pass
    def do_GET(s):
        t = parse_qs(urlparse(s.path).query, keep_blank_values=True).get("q", [""])[0]
        if "'1'='2" in t: _send(s, "<div>no results found</div>", "text/html")
        elif "'1'='1" in t or not t.endswith("'"):
            _send(s, "<div>post1</div><div>post2</div><div>post3</div>", "text/html")
        else: _send(s, "<div></div>", "text/html")


class SqliTime(BaseHTTPRequestHandler):
    """Blind time-based SQLi: no error, no boolean difference — the ONLY tell is
    a delay when a sleep/pg_sleep/WAITFOR is injected. Normal requests are fast."""
    def log_message(s, *a): pass
    def do_GET(s):
        from urllib.parse import unquote_plus
        q = unquote_plus(urlparse(s.path).query)
        m = re.search(r"(?:sleep|pg_sleep|waitfor\s+delay)\D*(\d+)", q, re.I)
        if m:
            _time.sleep(min(int(m.group(1)), 3))
        _send(s, "<div>post1</div><div>post2</div>", "text/html")   # always identical


class SqliSlowBenign(BaseHTTPRequestHandler):
    """Uniformly slow endpoint, identical body, not injectable — the time-based
    SQLi probe must measure DELTA (≈0 here) and reject it."""
    def log_message(s, *a): pass
    def do_GET(s):
        _time.sleep(0.8)
        _send(s, "<div>post1</div><div>post2</div>", "text/html")


class XssHtml(BaseHTTPRequestHandler):
    def log_message(s, *a): pass
    def do_GET(s):
        t = parse_qs(urlparse(s.path).query, keep_blank_values=True).get("search", [""])[0]
        _send(s, f"<section><h1>0 results for {t}</h1></section>", "text/html")


class XssAttribute(BaseHTTPRequestHandler):
    def log_message(s, *a): pass
    def do_GET(s):
        t = parse_qs(urlparse(s.path).query, keep_blank_values=True).get("search", [""])[0]
        _send(s, f'<input type="text" name="search" value="{t}">', "text/html")


class XssEvalSink(BaseHTTPRequestHandler):
    def log_message(s, *a): pass
    def do_GET(s):
        t = parse_qs(urlparse(s.path).query, keep_blank_values=True).get("SearchTerm", [""])[0]
        _send(s, '{"results":[],"searchTerm":"' + t + '"}', "application/json")


class XssJsString(BaseHTTPRequestHandler):
    """Input reflected INSIDE a single-quoted JS string in a <script> block —
    needs a ' break-out, NOT an <img> tag. A common beginner trap."""
    def log_message(s, *a): pass
    def do_GET(s):
        t = parse_qs(urlparse(s.path).query, keep_blank_values=True).get("search", [""])[0]
        _send(s, f"<html><body><script>var q = '{t}'; render(q);</script></body></html>", "text/html")


class XssComment(BaseHTTPRequestHandler):
    """Input reflected inside an HTML comment — must close the comment first
    with --> before a tag will run."""
    def log_message(s, *a): pass
    def do_GET(s):
        t = parse_qs(urlparse(s.path).query, keep_blank_values=True).get("search", [""])[0]
        _send(s, f"<div><!-- you searched for {t} --></div>", "text/html")


class BenignEscaped(BaseHTTPRequestHandler):
    """Input is reflected but safely HTML-encoded — confirm MUST reject."""
    def log_message(s, *a): pass
    def do_GET(s):
        t = parse_qs(urlparse(s.path).query, keep_blank_values=True).get("search", [""])[0]
        _send(s, f"<h1>0 results for {_html.escape(t)}</h1>", "text/html")


class Traversal(BaseHTTPRequestHandler):
    """A vulnerable file loader: the filename param reaches the filesystem."""
    def log_message(s, *a): pass
    def do_GET(s):
        from urllib.parse import unquote
        fn = unquote(parse_qs(urlparse(s.path).query, keep_blank_values=True).get("filename", [""])[0])
        if "carlos/secret" in fn:
            _send(s, "SECRET_FLAG_abc123", "text/plain")
        elif "etc/passwd" in fn:
            _send(s, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", "text/plain")
        else:
            _send(s, "\xff\xd8\xff image bytes", "image/jpeg")


def _send_cors(h, body, origin, acao):
    b = body.encode()
    h.send_response(200); h.send_header("Content-Type", "application/json")
    if acao:
        h.send_header("Access-Control-Allow-Origin", acao)
        h.send_header("Access-Control-Allow-Credentials", "true")
    h.send_header("Content-Length", str(len(b))); h.end_headers(); h.wfile.write(b)


class CorsReflect(BaseHTTPRequestHandler):
    """Vulnerable CORS: reflects ANY Origin into ACAO with credentials=true, and
    returns secret account data. An attacker page on any origin can read it."""
    def log_message(s, *a): pass
    def do_GET(s):
        origin = s.headers.get("Origin", "")
        _send_cors(s, '{"apikey":"SECRET_FLAG_abc123"}', origin, origin or None)


class CorsTrustedOnly(BaseHTTPRequestHandler):
    """Benign CORS: reflects ONLY its own trusted origin (a strict allow-list), so
    an attacker origin is never echoed. confirm_cors MUST reject this."""
    TRUSTED = "https://0aXXlab.web-security-academy.net"
    def log_message(s, *a): pass
    def do_GET(s):
        origin = s.headers.get("Origin", "")
        acao = s.TRUSTED if origin == s.TRUSTED else None
        _send_cors(s, '{"apikey":"SECRET_FLAG_abc123"}', origin, acao)


class Ssti(BaseHTTPRequestHandler):
    """A template-injectable view: the `message` param is rendered, so a template
    expression like {{7*7}} / ${7*7} / #{7*7} / <%=7*7%> evaluates to 49.
    Arithmetic only — safe and self-verifying."""
    def log_message(s, *a): pass
    def do_GET(s):
        from urllib.parse import unquote
        t = unquote(parse_qs(urlparse(s.path).query, keep_blank_values=True).get("message", [""])[0])

        def ev(m):
            expr = m.group(1).strip()
            if expr == "7*7":
                return "49"
            return m.group(0)
        out = t
        out = re.sub(r"\{\{\s*(.+?)\s*\}\}", ev, out)   # Jinja2 / Twig
        out = re.sub(r"\$\{\s*(.+?)\s*\}", ev, out)      # Java EL / Smarty
        out = re.sub(r"#\{\s*(.+?)\s*\}", ev, out)       # Ruby / Thymeleaf
        out = re.sub(r"<%=\s*(.+?)\s*%>", ev, out)       # ERB
        _send(s, f"<p>No such product: {out}</p>", "text/html")


class SstiErb(BaseHTTPRequestHandler):
    """SSTI where ONLY ERB <%= … %> evaluates — proves the engine fingerprint
    isn't hard-wired to Jinja. confirm_ssti should report ERB/Freemarker."""
    def log_message(s, *a): pass
    def do_GET(s):
        from urllib.parse import unquote
        t = unquote(parse_qs(urlparse(s.path).query, keep_blank_values=True).get("message", [""])[0])
        out = re.sub(r"<%=\s*(.+?)\s*%>", lambda m: "49" if m.group(1).strip() == "7*7" else m.group(0), t)
        _send(s, f"<p>No such product: {out}</p>", "text/html")


class CorsNullOnly(BaseHTTPRequestHandler):
    """Credentialed API that trusts ONLY Origin: null (the sandboxed-iframe case).
    confirm_cors should confirm via the null-origin branch."""
    def log_message(s, *a): pass
    def do_GET(s):
        origin = s.headers.get("Origin", "")
        acao = "null" if origin == "null" else None
        _send_cors(s, '{"apikey":"SECRET_FLAG_abc123"}', origin, acao)


class BenignTemplate(BaseHTTPRequestHandler):
    """Reflects `message` but is NOT a template engine — {{7*7}} comes back as
    literal text. confirm_ssti MUST reject this."""
    def log_message(s, *a): pass
    def do_GET(s):
        from urllib.parse import unquote
        t = unquote(parse_qs(urlparse(s.path).query, keep_blank_values=True).get("message", [""])[0])
        _send(s, f"<p>No such product: {_html.escape(t)}</p>", "text/html")


class CmdiTime(BaseHTTPRequestHandler):
    """Blind OS command injection confirmable only by TIMING: a `sleep N` in any
    param actually delays the response. Normal requests are fast."""
    def log_message(s, *a): pass
    def do_GET(s):
        from urllib.parse import unquote_plus
        q = unquote_plus(urlparse(s.path).query)   # a real server decodes before the shell sees it
        m = re.search(r"sleep\s+(\d+)", q)
        if m:
            _time.sleep(min(int(m.group(1)), 3))   # capped so the benchmark stays quick
        _send(s, "<p>image rendered</p>", "text/html")


class CmdiSlowBenign(BaseHTTPRequestHandler):
    """A uniformly SLOW endpoint that does NOT run commands — every response is
    delayed the same amount. The time-based probe must NOT be fooled: the delta
    between baseline and injected is ~0, so confirm must reject it."""
    def log_message(s, *a): pass
    def do_GET(s):
        _time.sleep(0.8)
        _send(s, "<p>image rendered</p>", "text/html")


class Ssrf(BaseHTTPRequestHandler):
    """A vulnerable URL fetcher: the url param is fetched server-side."""
    def log_message(s, *a): pass
    def do_GET(s):
        from urllib.parse import unquote
        u = unquote(parse_qs(urlparse(s.path).query, keep_blank_values=True).get("url", [""])[0])
        if u.startswith("file:") and "carlos/secret" in u:
            _send(s, "SECRET_FLAG_abc123", "text/plain")
        elif u.startswith("file:") and "passwd" in u:
            _send(s, "root:x:0:0:root:/root:/bin/bash", "text/plain")
        elif any(h in u for h in ("localhost", "127.0.0.1", "169.254.169.254")):
            _send(s, "Internal admin panel — not for public access", "text/html")
        elif u:
            _send(s, "In stock: 42 units", "text/html")   # external fetch
        else:
            _send(s, "provide a url", "text/html")
