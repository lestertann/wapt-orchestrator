"""Detectors = the playbook's "identify — signal -> likely bug" rows, as code.

Each detector is a small function:  (txn, ctx) -> Iterable[Signal].
It reads a captured Transaction passively (and ctx, a few cross-request facts)
and emits Signals. The triage layer groups Signals into Candidates per class.

Adding coverage later = write one more function and tag it with @detector(stage).
That extensibility is the whole point of the design.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Callable

from .models import Confidence as C, Signal, Stage, Transaction

# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
_REGISTRY: dict[Stage, list[Callable]] = {Stage.FOOTHOLD: [], Stage.PRIVESC: [], Stage.EXFIL: []}


def detector(stage: Stage):
    def wrap(fn):
        _REGISTRY[stage].append(fn)
        return fn
    return wrap


def detectors_for(stage: Stage) -> list[Callable]:
    return _REGISTRY[stage]


# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #
# PortSwigger lab chrome — not the target app. Anything here is noise.
_LAB_INFRA = (
    "/academylabheader", "/resources/labheader", "/resources/css/",
    "/resources/js/labheader", "submitsolution", "/resources/images/",
)


def is_lab_infra(url: str) -> bool:
    u = url.lower()
    return any(seg in u for seg in _LAB_INFRA)


# param names that are server-issued tokens — reflecting these is not XSS
_TOKEN_PARAMS = {"csrf", "_csrf", "token", "nonce", "csrftoken", "csrf_token",
                 "authenticity_token", "__requestverificationtoken"}


def _body(t: Transaction) -> str:
    return t.resp_body or ""


def _ct(t: Transaction) -> str:
    return (t.header("content-type") or "").lower()


def _set_cookie(t: Transaction) -> str:
    # resp_headers may fold multiple Set-Cookie; search both header + raw
    sc = t.resp_headers_lower.get("set-cookie", "")
    return sc


def _all_cookies(t: Transaction) -> str:
    return (t.req_headers.get("Cookie", "") + " " + _set_cookie(t))


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
_PARAMS_RE = re.compile(r"[?&]([A-Za-z0-9_\[\]]+)=")


def _jwt_header(token: str) -> dict:
    """Base64url-decode a JWT's first segment to read alg / kid / jwk / jku."""
    try:
        import base64 as _b64, json as _json
        h = token.split(".", 1)[0]
        h += "=" * (-len(h) % 4)
        obj = _json.loads(_b64.urlsafe_b64decode(h.encode()))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _params(t: Transaction) -> list[str]:
    return _PARAMS_RE.findall(t.url) + _PARAMS_RE.findall("?" + (t.req_body or ""))


# =========================================================================== #
# STAGE 1 — FOOTHOLD
# =========================================================================== #
@detector(Stage.FOOTHOLD)
def d_dom_xss(t, ctx) -> Iterable[Signal]:
    """JS location.* flows into innerHTML/eval -> DOM XSS."""
    if is_lab_infra(t.url):
        return  # labHeader.js etc. is lab chrome, its postMessage/eval is not the target
    if "javascript" not in _ct(t) and ".js" not in t.url and "html" not in _ct(t):
        return
    b = _body(t)
    if not b:
        return
    sources = re.findall(r"location\.(?:search|hash|href)|location\b|document\.(?:URL|referrer)|window\.name", b)
    sinks = re.findall(r"\.innerHTML|document\.write|\beval\(|\bFunction\(|\.outerHTML|setTimeout\(|insertAdjacentHTML|\.src\s*=|location\s*=", b)
    if sources and sinks:
        # eval()/Function() on a URL-controlled source = direct code execution
        # (the classic reflected-into-eval DOM XSS); rank it HIGH, others MEDIUM.
        code_sink = next((s for s in sinks if "eval(" in s or "Function(" in s), "")
        conf = C.HIGH if code_sink else C.MEDIUM
        sink = code_sink or sinks[0]
        yield Signal("dom-xss",
                     f"JS source ({sources[0]}) flows to sink ({sink.strip()}) in "
                     + t.url.rsplit('/', 1)[-1]
                     + (" — reflected-into-eval, steal the cookie" if code_sink else ""),
                     conf, t.url, evidence=f"{sources[0]} … {sink}", txn=t)


@detector(Stage.FOOTHOLD)
def d_web_message(t, ctx) -> Iterable[Signal]:
    """postMessage handler with no origin check -> web-message XSS."""
    b = _body(t)
    if "addEventListener" in b and "message" in b:
        m = b.find("message")
        block = b[max(0, m - 60): m + 400]
        if "addEventListener" in block and "origin" not in block:
            yield Signal("web-message-xss",
                         "message listener without an e.origin check",
                         C.MEDIUM, t.url, evidence="addEventListener('message',…) no origin", txn=t)


@detector(Stage.FOOTHOLD)
def d_reflected_input(t, ctx) -> Iterable[Signal]:
    """search/comment reflects input -> reflected/stored XSS."""
    b = _body(t)
    for p in _params(t):
        if p.lower() in _TOKEN_PARAMS:
            continue  # reflecting a CSRF token / nonce is normal, not XSS
        val = _qval(t.url, p) or _qval("?" + (t.req_body or ""), p)
        if not val or len(val) < 3 or not _looks_textual(val) or val not in b:
            continue
        yield Signal("reflected-stored-xss",
                     f"param '{p}' reflected unencoded in the response body",
                     C.MEDIUM, f"{t.url}  (param {p})", evidence=val[:60], txn=t)
        break


@detector(Stage.FOOTHOLD)
def d_cache(t, ctx) -> Iterable[Signal]:
    """X-Cache: hit + a cached .js -> cache poisoning."""
    xc = (t.header("x-cache") or "").lower()
    age = t.header("age")
    if ("hit" in xc or age) and (".js" in t.url or "javascript" in _ct(t)):
        yield Signal("cache-poisoning",
                     f"cacheable script served from cache (X-Cache:{xc or '-'} Age:{age or '-'})",
                     C.MEDIUM, t.url, evidence=f"X-Cache:{xc} Age:{age}", txn=t)


@detector(Stage.FOOTHOLD)
def d_host_reflect(t, ctx) -> Iterable[Signal]:
    """Host trusted -> reset poisoning, localhost auth bypass, or routing SSRF."""
    host = t.req_headers.get("Host", "")
    b = _body(t)
    is_resetish = any(k in t.url.lower() for k in ("forgot", "reset", "password"))
    if host and host in b and (is_resetish or "http://" + host in b or "https://" + host in b):
        yield Signal("host-header",
                     "request Host value reflected into response/link",
                     C.MEDIUM if is_resetish else C.LOW,
                     t.url, evidence=host, txn=t)
    # X-Forwarded-Host reflected -> password-reset poisoning / link injection
    xfh = t.req_headers.get("X-Forwarded-Host") or t.req_headers.get("x-forwarded-host", "")
    if xfh and xfh in b:
        yield Signal("host-header",
                     "X-Forwarded-Host reflected into response/link — reset-poisoning surface",
                     C.MEDIUM if is_resetish else C.LOW,
                     t.url, evidence="XFH: " + xfh, txn=t)
    # localhost / 127.0.0.1 admin bypass — the app gates /admin on locality,
    # which the Host header controls. Tell: an admin page that says "local only".
    if re.search(r"/admin\b", t.url, re.I) and \
       re.search(r"local users|only.{0,25}local|localhost|127\.0\.0\.1|internal only", b, re.I):
        yield Signal("host-header",
                     "admin restricted to local users — set Host: localhost (or 127.0.0.1) to bypass",
                     C.MEDIUM, t.url, evidence="local-only admin", txn=t)
    # Host already pointed at an internal name -> routing-based SSRF surface
    if host and re.search(r"^(localhost|127\.0\.0\.1|192\.168\.|10\.|169\.254\.)", host, re.I):
        yield Signal("host-header",
                     "Host set to an internal address — routing-based SSRF / local-access test",
                     C.LOW, t.url, evidence="Host: " + host, txn=t)


@detector(Stage.FOOTHOLD)
def d_smuggle(t, ctx) -> Iterable[Signal]:
    """scanner flags a smuggle (200 not 400) / TE+CL present -> request smuggling."""
    te = t.req_headers.get("Transfer-Encoding", "")
    cl = t.req_headers.get("Content-Length", "")
    if te and cl:
        yield Signal("request-smuggling",
                     "both Transfer-Encoding and Content-Length present on one request",
                     C.MEDIUM, t.url, evidence=f"TE:{te} CL:{cl}", txn=t)


@detector(Stage.FOOTHOLD)
def d_login_enum(t, ctx) -> Iterable[Signal]:
    """login error wording/timing differs -> user enum + brute (incl. 2FA step).
    Also fires on the login PAGE itself (GET): an auth foothold produces no
    reflection, so the presence of a username+password form — especially with a
    password-reset flow and no self-registration — IS the lead to enumerate and
    brute-force. Without this, a canary crawl sees a login app and reports
    nothing, which is exactly the blind spot on auth-based Stage 1 exams."""
    b = _body(t)
    # a) an explicit auth POST (login / 2FA submit)
    if re.search(r"/(log-?in\d?|login\d?|authenticate|mfa|totp|2fa|verify|sign-?in)\b", t.url, re.I) \
       and t.method == "POST":
        yield Signal("user-enum-brute",
                     "auth/login POST present — diff valid/invalid username, status, timing; or brute the 2FA code",
                     C.MEDIUM, t.url, evidence=f"status {t.status}", txn=t)
    # b) the login PAGE itself — a password field + a username/email field
    has_pw = re.search(r'type=["\']?password', b, re.I) is not None
    has_user = re.search(r'name=["\']?(username|user|email|login)\b', b, re.I) is not None
    if has_pw and has_user:
        reset = re.search(r'forgot|reset|refreshpassword', b + t.url, re.I) is not None
        # The mere presence of a login form is only a WEAK hint — many labs have
        # a login but the real foothold is elsewhere (DOM XSS, etc.). Keep this
        # LOW so a confirmed reflection/DOM/SQLi finding always outranks it;
        # it becomes the lead only when nothing stronger is found.
        extra = " + password-reset flow" if reset else ""
        yield Signal("user-enum-brute",
                     "login form present" + extra +
                     " — IF nothing else lands, enumerate a username then brute the password (Burp Intruder)",
                     C.LOW, t.url, evidence="login form" + extra, txn=t)


@detector(Stage.FOOTHOLD)
def d_oauth(t, ctx) -> Iterable[Signal]:
    """'log in with…' social button / OAuth flow -> OAuth takeover."""
    if re.search(r"/(auth|oauth|authorize|callback)\b", t.url, re.I) or \
       re.search(r"client_id=|redirect_uri=|response_type=", t.url + (t.req_body or "")):
        missing_state = "state=" not in (t.url + (t.req_body or ""))
        yield Signal("oauth-takeover",
                     "OAuth endpoint/params seen" + (" — no 'state' (CSRF-able linking)" if missing_state else ""),
                     C.MEDIUM if missing_state else C.LOW, t.url,
                     evidence="oauth flow", txn=t)


@detector(Stage.FOOTHOLD)
def d_cswsh(t, ctx) -> Iterable[Signal]:
    """wss:// chat / live feed -> CSWSH."""
    if is_lab_infra(t.url):
        return  # lab-status socket (academyLabHeader) is PortSwigger chrome, not the app
    upg = (t.header("upgrade") or t.req_headers.get("Upgrade", "")).lower()
    if "websocket" in upg or t.status == 101 or "wss://" in _body(t):
        has_token = bool(re.search(r"csrf|x-csrf|sec-websocket-protocol", str(t.req_headers), re.I))
        yield Signal("cswsh",
                     "WebSocket handshake" + ("" if has_token else " with cookie-only auth (hijackable)"),
                     C.MEDIUM if not has_token else C.LOW, t.url, evidence="Upgrade: websocket", txn=t)


@detector(Stage.FOOTHOLD)
def d_content_disc(t, ctx) -> Iterable[Signal]:
    """hidden endpoints, backups, git, secrets, verbose errors."""
    u = t.url.lower()
    if any(k in u for k in ("/.git", "/backup", "~", "robots.txt", "sitemap.xml", ".bak", ".old", ".env", ".sql")):
        yield Signal("content-discovery", f"sensitive path exposed: {u.rsplit('/',1)[-1]}",
                     C.HIGH if t.status == 200 else C.LOW, t.url, evidence=f"status {t.status}", txn=t)
    # an endpoint that EXISTS but is access-controlled — the recon win that
    # points straight at the Stage 2 target (admin panel / internal API).
    if t.status in (401, 403) and re.search(r"/(admin|console|panel|manage|management|internal|api|actuator|metrics)\b", u):
        name = t.url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
        yield Signal("content-discovery",
                     f"protected endpoint found ({t.status}): /{name} — access-control / privesc target",
                     C.MEDIUM, t.url, evidence=f"status {t.status}", txn=t)
    if t.status and t.status >= 500 and re.search(r"stack trace|exception|at [\w.]+\(|SQLSTATE|Traceback", _body(t), re.I):
        yield Signal("content-discovery", "verbose error / stack trace disclosed",
                     C.MEDIUM, t.url, evidence="error page", txn=t)
    # debug / info pages that leak internals or secrets (any status)
    if re.search(r"phpinfo\(\)|PHP Version|SECRET_KEY|DEBUG\s*=\s*True|Whitelabel Error|"
                 r"django\.core|Werkzeug Debugger|X-Powered-By", _body(t), re.I):
        yield Signal("content-discovery", "debug/info page leaks internals or secrets",
                     C.MEDIUM, t.url, evidence="debug page", txn=t)


# =========================================================================== #
# STAGE 2 — PRIVESC
# =========================================================================== #
@detector(Stage.PRIVESC)
def d_sqli(t, ctx) -> Iterable[Signal]:
    """'advanced search' / TrackingId cookie -> SQL injection."""
    cookies = _all_cookies(t)
    if re.search(r"TrackingId=", cookies):
        yield Signal("sql-injection", "TrackingId cookie present (classic SQLi sink)",
                     C.MEDIUM, t.url, evidence="TrackingId cookie", txn=t)
    if re.search(r"[?&](search|category|query|q|filter|sort)=", t.url, re.I):
        yield Signal("sql-injection", "search/filter param (active-scan it for SQLi)",
                     C.LOW, t.url, evidence="search param", txn=t)
    if re.search(r"SQL syntax|SQLSTATE|ORA-\d|PG::|psql|unclosed quotation", _body(t), re.I):
        yield Signal("sql-injection", "SQL error string in response (error-based SQLi)",
                     C.HIGH, t.url, evidence="sql error", txn=t)


@detector(Stage.PRIVESC)
def d_mass_assign(t, ctx) -> Iterable[Signal]:
    """change-email response leaks roleid -> mass-assign / IDOR.

    Tightened: a privilege field (roleid/isAdmin/role/...) anywhere is a strong
    hit; a plain 'id'/'userid' only counts on an account-type endpoint — a blog
    post's "id":5 in search results is NOT a mass-assignment signal.
    """
    if "json" not in _ct(t):
        return
    b = _body(t)
    account_ep = bool(re.search(r"account|profile|/user\b|/users\b|change-email|update-?email|settings", t.url, re.I))
    priv = re.search(r'"(roleid|isAdmin|is_admin|role|privilege|access_?level|is_?staff|admin)"\s*:', b, re.I)
    if priv:
        yield Signal("idor-mass-assign",
                     f"response JSON exposes privilege field '{priv.group(1)}' (mass-assign target)",
                     C.HIGH if account_ep else C.MEDIUM, t.url,
                     evidence=priv.group(0)[:60], txn=t)
        return
    idf = re.search(r'"(userid|user_id|accountId|id)"\s*:', b, re.I)
    if idf and account_ep:
        yield Signal("idor-mass-assign",
                     f"account endpoint returns '{idf.group(1)}' (IDOR / tamper target)",
                     C.MEDIUM, t.url, evidence=idf.group(0)[:60], txn=t)


@detector(Stage.PRIVESC)
def d_method_access(t, ctx) -> Iterable[Signal]:
    """admin action refused on its real verb -> method-based access control.

    When a privileged action (admin-roles, user upgrade, admin delete) returns
    401/403 to a POST/PUT/DELETE, the access check may be bound to the HTTP
    method: retry with GET / HEAD / an unexpected method (POSTX) or an
    X-Original-URL / X-Override-URL header.
    """
    if is_lab_infra(t.url):
        return
    admin_ep = re.search(r"/admin\b|/admin-roles|/admin/|upgrade|downgrade|"
                         r"delete\?username|/manage|setrole|role=", t.url + " " + (t.req_body or ""), re.I)
    if admin_ep and t.status in (401, 403) and t.method in ("POST", "PUT", "DELETE", "PATCH"):
        yield Signal("idor-mass-assign",
                     f"{t.method} {t.status} on an admin action — try a method change "
                     f"(GET/HEAD/POSTX) or X-Original-URL to bypass method-based access control",
                     C.HIGH, t.url, evidence=f"{t.method} -> {t.status}", txn=t)


@detector(Stage.PRIVESC)
def d_csrf(t, ctx) -> Iterable[Signal]:
    """state-changing POST, weak/absent token -> CSRF takeover."""
    if t.method == "POST" and re.search(r"change-email|change-password|my-account|update|email", t.url, re.I):
        body = t.req_body or ""
        has_csrf = "csrf" in body.lower() or "csrf" in str(t.req_headers).lower()
        samesite = "samesite" in _set_cookie(t).lower()
        if not has_csrf:
            yield Signal("csrf-takeover",
                         "state-changing POST with no CSRF token in body",
                         C.MEDIUM, t.url, evidence="no csrf param", txn=t)
        elif not samesite:
            yield Signal("csrf-takeover",
                         "state-changing POST; token present — check if tied to session / SameSite",
                         C.LOW, t.url, evidence="csrf present", txn=t)


@detector(Stage.PRIVESC)
def d_reset_logic(t, ctx) -> Iterable[Signal]:
    """reset token not tied to the user -> password-reset logic."""
    if re.search(r"forgot-password|reset-password|change-password", t.url, re.I):
        if re.search(r"token=|temp-forgot-password-token", t.url + (t.req_body or "")):
            yield Signal("password-reset-logic",
                         "reset token in request — test: drop it, set username=administrator",
                         C.MEDIUM, t.url, evidence="reset token param", txn=t)


@detector(Stage.PRIVESC)
def d_jwt(t, ctx) -> Iterable[Signal]:
    """3-part xxx.yyy.zzz token -> JWT forge.

    Decodes the header so the board names the *specific* attack rather than a
    generic "JWT present": alg:none, algorithm-confusion (RS256->HS256 with the
    public key from /jwks.json), kid header path-traversal, jwk/jku injection,
    or weak-HMAC-secret crack. Each of those was a distinct lab.
    """
    hay = _all_cookies(t) + " " + t.req_headers.get("Authorization", "") + " " + (t.req_body or "")
    m = _JWT_RE.search(hay)
    if not m:
        return
    tok = m.group(0)
    hdr = _jwt_header(tok)
    alg = str(hdr.get("alg", "")).lower()
    attacks, conf = [], C.MEDIUM
    if alg in ("none", ""):
        attacks.append("alg:none -> strip the signature, set sub=administrator")
        conf = C.HIGH
    if "kid" in hdr:
        attacks.append("kid header -> path-traversal to an empty file (e.g. /dev/null) + HMAC-sign with k='AA=='; or SQLi via kid")
        conf = C.HIGH
    if "jku" in hdr or "x5u" in hdr:
        attacks.append("jku/x5u -> host your JWKS on the exploit server and point the header at it")
        conf = C.HIGH
    if "jwk" in hdr:
        attacks.append("jwk -> embed your own public key in the header (JWT Editor: Embedded JWK)")
        conf = C.HIGH
    if alg.startswith(("rs", "es", "ps")):
        attacks.append("asymmetric alg -> algorithm confusion: fetch the public key from /jwks.json, sign HS256 with it as the secret")
    if alg.startswith("hs"):
        attacks.append("HMAC -> crack a weak secret (hashcat -m 16500 jwt.secrets.list) then re-sign")
    label = ("JWT (alg=%s) -> " % (alg or "?")) + "; ".join(attacks) if attacks \
        else "JWT present — check whether the signature is verified"
    yield Signal("jwt-forge", label, conf, t.url, evidence=tok[:40] + "…", txn=t)


@detector(Stage.PRIVESC)
def d_cors(t, ctx) -> Iterable[Signal]:
    """Origin reflected + creds returned -> CORS exfil."""
    acao = t.header("access-control-allow-origin")
    acac = (t.header("access-control-allow-credentials") or "").lower()
    origin = t.req_headers.get("Origin", "")
    if acao and (acao == origin or acao == "null" or (origin and acao == origin)):
        if acac == "true":
            yield Signal("cors-exfil",
                         f"ACAO reflects Origin ({acao}) with Allow-Credentials:true",
                         C.HIGH, t.url, evidence=f"ACAO:{acao} ACAC:true", txn=t)
        else:
            yield Signal("cors-exfil", f"ACAO reflects Origin ({acao}) — test with credentials",
                         C.LOW, t.url, evidence=f"ACAO:{acao}", txn=t)


@detector(Stage.PRIVESC)
def d_api(t, ctx) -> Iterable[Signal]:
    """/api docs, extra HTTP verbs, GraphQL -> API / mass-assign."""
    u = t.url.lower()
    if "/graphql" in u or "query{" in (t.req_body or "").replace(" ", "") or "__schema" in (t.req_body or ""):
        yield Signal("api-graphql", "GraphQL endpoint — try introspection", C.MEDIUM, t.url,
                     evidence="graphql", txn=t)
    elif re.search(r"/api/|/v\d/|swagger|openapi|/rest/", u):
        yield Signal("api-graphql", "API surface — enumerate verbs/docs, mass-assign fields",
                     C.LOW, t.url, evidence="api path", txn=t)


@detector(Stage.PRIVESC)
def d_proto_client(t, ctx) -> Iterable[Signal]:
    """__proto__ honored in JSON/URL -> prototype pollution (client-side here)."""
    if "__proto__" in (t.url + (t.req_body or "")):
        yield Signal("client-side-proto-pollution", "__proto__ seen in URL/body",
                     C.MEDIUM, t.url, evidence="__proto__", txn=t)


# =========================================================================== #
# STAGE 3 — EXFIL
# =========================================================================== #
@detector(Stage.EXFIL)
def d_cmdi(t, ctx) -> Iterable[Signal]:
    """image size param / feedback email / XML field -> OS command injection."""
    blob = t.url + " " + (t.req_body or "")
    if re.search(r"(ImgSize|imageSize|size|width|height)=", blob) and re.search(r"image|img", blob, re.I):
        yield Signal("os-command-injection",
                     "image endpoint with a size param (backtick cmdi sink)",
                     C.MEDIUM, t.url, evidence="size param on image", txn=t)
    if re.search(r"/(feedback|contact)\b", t.url, re.I) and "email" in blob.lower():
        yield Signal("os-command-injection", "feedback/contact email field (cmdi sink)",
                     C.LOW, t.url, evidence="feedback email", txn=t)


@detector(Stage.EXFIL)
def d_traversal(t, ctx) -> Iterable[Signal]:
    """image loader with no size param / file param -> traversal / LFI."""
    if re.search(r"(file_?name|imagefile|filename|path|doc|page|template|load)=", t.url, re.I):
        has_size = re.search(r"(ImgSize|size|width|height)=", t.url, re.I)
        if not has_size:
            yield Signal("path-traversal",
                         "file/image loader param with no size param (traversal/LFI)",
                         C.MEDIUM, t.url, evidence="file param", txn=t)


@detector(Stage.EXFIL)
def d_ssti(t, ctx) -> Iterable[Signal]:
    """reset-email template editor / 'out of stock' reflecting input -> SSTI."""
    if re.search(r"template|email-template|preview", t.url, re.I):
        yield Signal("ssti", "template/email editor endpoint (classic SSTI sink)",
                     C.MEDIUM, t.url, evidence="template editor", txn=t)
    if re.search(r"out of stock|out-of-stock", _body(t), re.I):
        yield Signal("ssti", "'out of stock' view reflects input (SSTI candidate)",
                     C.LOW, t.url, evidence="stock view", txn=t)


@detector(Stage.EXFIL)
def d_xxe(t, ctx) -> Iterable[Signal]:
    """XML *request* body / upload -> XXE. (Response-side XML like .svg images
    is deliberately ignored — that's not an injection sink.)"""
    req_ct = t.req_headers.get("Content-Type", "").lower()
    rb = (t.req_body or "").lstrip()
    if "xml" in req_ct or rb.startswith("<?xml") or \
       (t.method in ("POST", "PUT") and re.search(r"<\w+>.*</\w+>", rb[:300])):
        yield Signal("xxe", "XML request body/upload (XXE candidate)",
                     C.MEDIUM, t.url, evidence="xml request body", txn=t)


@detector(Stage.EXFIL)
def d_ssrf(t, ctx) -> Iterable[Signal]:
    """'download report / generate file' + URL, or server-fetch-by-URL -> SSRF."""
    blob = t.url + " " + (t.req_body or "")
    if re.search(r"(url|uri|path|dest|redirect|stockApi|imageUrl|fetch|callback|PageHtml)=\s*https?", blob, re.I) \
       or re.search(r'"(url|stockApi|imageUrl|PageHtml)"\s*:', blob, re.I):
        yield Signal("ssrf", "param carries a URL the server fetches (SSRF)",
                     C.MEDIUM, t.url, evidence="url param", txn=t)
    if re.search(r"report|generate|pdf|preview|stock-?check", t.url, re.I):
        yield Signal("ssrf", "report/PDF/stock-check feature (SSRF / file-read via PDF)",
                     C.LOW, t.url, evidence="report feature", txn=t)


@detector(Stage.EXFIL)
def d_upload(t, ctx) -> Iterable[Signal]:
    """avatar upload / set-image-by-URL -> file upload RCE / RFI."""
    multipart = "multipart/form-data" in t.req_headers.get("Content-Type", "").lower()
    # only a *submission* is an upload sink — not a GET of an avatar image
    if multipart or (t.method in ("POST", "PUT") and
                     re.search(r"upload|avatar|/import\b|profile-image", t.url, re.I)):
        yield Signal("file-upload-rce", "file upload submission — probe extension/type/path controls",
                     C.MEDIUM, t.url, evidence="upload submission", txn=t)


@detector(Stage.EXFIL)
def d_deser(t, ctx) -> Iterable[Signal]:
    """serialized / gzip blob in a cookie -> deserialization."""
    cookies = _all_cookies(t)
    # Java rO0AB (base64 ac ed 00 05), gzip H4sI, PHP O:/a:, Ruby \x04\x08
    if re.search(r"=rO0AB|=H4sI|=(?:O|a):\d+:|%3A\d+%3A", cookies):
        kind = "Java" if "rO0AB" in cookies else ("gzip" if "H4sI" in cookies else "PHP")
        yield Signal("deserialization", f"serialized {kind} blob in a cookie",
                     C.HIGH, t.url, evidence="serialized cookie", txn=t)


@detector(Stage.EXFIL)
def d_proto_server(t, ctx) -> Iterable[Signal]:
    """__proto__ changes server behavior -> server-side proto pollution."""
    if "__proto__" in (t.req_body or "") and "json" in t.req_headers.get("Content-Type", "").lower():
        yield Signal("server-side-proto-pollution", "__proto__ in a JSON request body (SSPP)",
                     C.MEDIUM, t.url, evidence="__proto__ json", txn=t)


# --------------------------------------------------------------------------- #
# small text helpers
# --------------------------------------------------------------------------- #
def _qval(url: str, param: str) -> str | None:
    m = re.search(rf"[?&]{re.escape(param)}=([^&#]*)", url)
    if not m:
        return None
    from urllib.parse import unquote_plus
    return unquote_plus(m.group(1))


def _looks_textual(v: str) -> bool:
    return bool(re.search(r"[A-Za-z]", v)) and not v.isdigit()
