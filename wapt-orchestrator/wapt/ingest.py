"""Turn a source of traffic into a list of Transaction objects.

Three input paths, best-to-worst for fidelity:

  1. Burp XML export  (Proxy > HTTP history > select > right-click > "Save items")
     -> perfect request/response pairing, base64 payloads. Use this for real work.
  2. HAR file         (browser devtools / many proxies export HAR)
     -> clean pairing.
  3. Raw .burp project save file
     -> PROPRIETARY binary; Burp needs its own index to pair req<->resp, which is
        not exported. We *carve* plaintext HTTP blocks and pair them by file order.
        Good enough to drive triage for a quick test; not authoritative.

Plus a tiny live crawler for the "just give it a URL" flow.
"""
from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

from .models import Transaction


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _split_head_body(raw: bytes) -> tuple[str, str]:
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        return raw.decode("latin1", "replace"), ""
    return raw[:sep].decode("latin1", "replace"), raw[sep + 4:].decode("latin1", "replace")


def _parse_req_head(head: str) -> tuple[str, str, dict[str, str]]:
    lines = head.split("\r\n")
    method, path = "GET", "/"
    if lines:
        parts = lines[0].split(" ")
        if len(parts) >= 2:
            method, path = parts[0], parts[1]
    headers = {}
    for ln in lines[1:]:
        if ": " in ln:
            k, v = ln.split(": ", 1)
            headers[k] = v
    return method, path, headers


def _parse_resp_head(head: str) -> tuple[int | None, dict[str, str]]:
    lines = head.split("\r\n")
    status = None
    if lines:
        m = re.match(r"HTTP/[\d.]+\s+(\d{3})", lines[0])
        if m:
            status = int(m.group(1))
    headers = {}
    for ln in lines[1:]:
        if ": " in ln:
            k, v = ln.split(": ", 1)
            headers[k] = v
    return status, headers


def _url_from_req(path: str, headers: dict[str, str], default_scheme="https") -> str:
    if path.startswith("http"):
        return path
    host = headers.get("Host") or headers.get("host") or "unknown.invalid"
    return f"{default_scheme}://{host}{path}"


# --------------------------------------------------------------------------- #
# 1. Burp XML export
# --------------------------------------------------------------------------- #
def from_burp_xml(path: str) -> list[Transaction]:
    txns: list[Transaction] = []
    tree = ET.parse(path)
    for item in tree.getroot().findall("item"):
        url = (item.findtext("url") or "").strip()
        req_el = item.find("request")
        resp_el = item.find("response")
        raw_req = _decode_el(req_el)
        raw_resp = _decode_el(resp_el)
        rhead, rbody = _split_head_body(raw_req)
        method, path, rh = _parse_req_head(rhead)
        shead, sbody = _split_head_body(raw_resp)
        status, sh = _parse_resp_head(shead)
        if not url:
            url = _url_from_req(path, rh)
        txns.append(Transaction(
            method=method or (item.findtext("method") or "GET"),
            url=url, req_headers=rh, req_body=rbody,
            status=status, resp_headers=sh, resp_body=sbody,
            meta={"source": "burp-xml"},
        ))
    return txns


def _decode_el(el) -> bytes:
    if el is None or el.text is None:
        return b""
    if el.get("base64") == "true":
        try:
            return base64.b64decode(el.text)
        except Exception:
            return el.text.encode("latin1", "replace")
    return el.text.encode("latin1", "replace")


# --------------------------------------------------------------------------- #
# 2. HAR
# --------------------------------------------------------------------------- #
def from_har(path: str) -> list[Transaction]:
    with open(path, encoding="utf-8") as fh:
        har = json.load(fh)
    txns = []
    for e in har.get("log", {}).get("entries", []):
        req, resp = e.get("request", {}), e.get("response", {})
        rh = {h["name"]: h["value"] for h in req.get("headers", [])}
        sh = {h["name"]: h["value"] for h in resp.get("headers", [])}
        txns.append(Transaction(
            method=req.get("method", "GET"),
            url=req.get("url", ""),
            req_headers=rh,
            req_body=(req.get("postData", {}) or {}).get("text", ""),
            status=resp.get("status"),
            resp_headers=sh,
            resp_body=(resp.get("content", {}) or {}).get("text", ""),
            meta={"source": "har"},
        ))
    return txns


# --------------------------------------------------------------------------- #
# 3. Raw .burp project save file  (best-effort carver)
# --------------------------------------------------------------------------- #
_REQ_RE = re.compile(
    rb"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) [^\r\n ]+ HTTP/(?:2|1\.[01])\r\n"
)
_RESP_RE = re.compile(rb"HTTP/(?:2|1\.[01])(?:\.[0-9])? [1-5][0-9][0-9][^\r\n]*\r\n")
_BODY_CAP = 200_000  # don't drag a whole 10MB response body into memory per txn


def from_burp_project(path: str, max_items: int | None = None) -> list[Transaction]:
    """Carve plaintext HTTP out of a proprietary .burp save file.

    Strategy: find every request-line and response-line offset, walk them in
    file order, and pair each request with the first response that appears
    before the next request. Bodies are read up to the next block start (capped).
    """
    data = open(path, "rb").read()

    blocks: list[tuple[int, str]] = []
    for m in _REQ_RE.finditer(data):
        blocks.append((m.start(), "req"))
    for m in _RESP_RE.finditer(data):
        blocks.append((m.start(), "resp"))
    blocks.sort()

    # offset -> end (start of next block) so we can bound each block's bytes
    starts = [b[0] for b in blocks]

    def block_bytes(idx: int) -> bytes:
        start = blocks[idx][0]
        end = starts[idx + 1] if idx + 1 < len(starts) else min(len(data), start + _BODY_CAP)
        return data[start:min(end, start + _BODY_CAP)]

    def looks_like_real_response(idx: int) -> bool:
        raw = block_bytes(idx)[:600]
        return bool(re.search(
            rb"\r\n(Server|Date|Content-Type|Content-Length|X-Cache|Set-Cookie|"
            rb"Connection|Location|Cache-Control): ", raw, re.I))

    txns: list[Transaction] = []
    i = 0
    n = len(blocks)
    while i < n:
        if blocks[i][1] != "req":
            i += 1
            continue
        raw_req = block_bytes(i)
        rhead, rbody = _split_head_body(raw_req)
        method, p, rh = _parse_req_head(rhead)
        # strip trailing binary garbage from a carved body at first NUL run
        rbody = _trim_binary(rbody)

        # find this request's response: first *real* response before next request
        status = sh = sbody = None
        j = i + 1
        while j < n and blocks[j][1] == "resp":
            if looks_like_real_response(j):
                shead, sbody_raw = _split_head_body(block_bytes(j))
                status, sh = _parse_resp_head(shead)
                sbody = _trim_binary(sbody_raw)
                j += 1
                break
            j += 1
        # advance past any responses we consumed/skipped until the next request
        nxt = i + 1
        while nxt < n and blocks[nxt][1] == "resp":
            nxt += 1

        txns.append(Transaction(
            method=method, url=_url_from_req(p, rh),
            req_headers=rh, req_body=rbody,
            status=status, resp_headers=sh or {}, resp_body=sbody or "",
            meta={"source": "burp-project(carved)",
                  "paired": status is not None},
        ))
        if max_items and len(txns) >= max_items:
            break
        i = nxt
    return txns


def _trim_binary(s: str) -> str:
    """A carved body runs into the next binary index record. Cut at the first
    run of NULs / non-text that marks the end of the real body."""
    m = re.search(r"[\x00-\x08\x0e-\x1f]{4,}", s)
    return s[:m.start()] if m else s


# --------------------------------------------------------------------------- #
# dispatcher + tiny live crawler
# --------------------------------------------------------------------------- #
def load_file(path: str, max_items: int | None = None) -> list[Transaction]:
    low = path.lower()
    if low.endswith(".burp"):
        return from_burp_project(path, max_items=max_items)
    if low.endswith(".har"):
        return from_har(path)
    if low.endswith(".xml"):
        return from_burp_xml(path)
    # sniff
    head = open(path, "rb").read(64)
    if head[:1] in (b"\xf0", b"\x00") or b"burp" in head.lower():
        return from_burp_project(path, max_items=max_items)
    if head.lstrip()[:1] == b"{":
        return from_har(path)
    return from_burp_xml(path)


def crawl(start_url: str, session, max_pages: int = 40) -> list[Transaction]:
    """Breadth-first same-origin crawl using the scoped HTTP session.
    Deliberately small: enough to feed triage, not a full spider."""
    seen: set[str] = set()
    queue = [start_url]
    txns: list[Transaction] = []
    origin = urlparse(start_url).netloc
    href_re = re.compile(r'(?:href|src|action)=["\']([^"\']+)["\']', re.I)

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        txn = session.fetch("GET", url)
        if txn is None:
            continue
        txns.append(txn)
        ct = txn.header("content-type") or ""
        if "html" not in ct and "javascript" not in ct:
            continue
        for href in href_re.findall(txn.resp_body or ""):
            nxt = urljoin(url, href)
            if urlparse(nxt).netloc == origin and nxt not in seen:
                queue.append(nxt)
    return txns
