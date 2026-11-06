"""Live mode: the engine runs as a small localhost server.

  - the thin Burp extension POSTs each proxy request/response to  POST /ingest
  - triage runs incrementally over everything seen so far
  - a web dashboard (GET /) polls  GET /api/state  and drives the gate with
    POST /api/proceed  /  POST /api/reset

Stdlib only (http.server). Shared state is guarded by one lock; triage is
recomputed lazily when the dashboard asks, not on every ingested packet, so a
flood of traffic doesn't thrash the CPU.
"""
from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import templating as T
from . import confirm as CF
from . import teach as TEACH
from .config import Config
from .dashboard import PAGE
from .http_client import ScopedSession
from .models import Stage, Transaction
from .triage import triage
from .agents import ExamCoordinator

# classes autopilot will auto-confirm (ones with a real safe probe)
_AUTO_CONFIRMABLE = {"sql-injection", "reflected-stored-xss", "dom-xss",
                     "ssrf", "os-command-injection", "path-traversal",
                     "ssti", "cors-exfil"}
_EXPLOIT_HOST_RE = re.compile(r"https?://(exploit-[a-z0-9]+\.exploit-server\.net)", re.I)


def _is_placeholder(host: str) -> bool:
    """A not-a-real-lab hostname shipped as a default or left over from setup —
    e.g. 0aXX.web-security-academy.net, YOUR-LAB…, 0aYY… . Real lab hosts are
    hex (0a1600fb…) and never contain xx/yy/your-."""
    h = (host or "").lower()
    return (not h) or "xx" in h or "yy" in h or h.startswith("your-") or "your-lab" in h


class LiveState:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.ph = cfg.placeholders()
        self.lock = threading.Lock()
        self.txns: list[Transaction] = []
        self.current = Stage.FOOTHOLD
        self._dirty = True
        self._cache: list = []
        self.started = time.time()
        self.last_ingest = 0.0
        self.seen_urls: set[str] = set()
        self.verdicts: dict[str, tuple[bool, str]] = {}   # cid -> (confirmed, note)
        self.ready: dict[str, list] = {}                  # cid -> extra Payload(s) from confirm
        self.session = ScopedSession(cfg)
        self.autopilot = (cfg.mode == "lab")   # auto-confirm on in lab mode by default
        self._auto_tried: set[str] = set()
        self.auto_status = "on" if self.autopilot else "off"
        self._crawling = False
        self.crawl_pages = 0
        self._autocrawled = False
        self.patterns_seen: set[str] = set()       # vuln classes the learner has met
        self.patterns_confirmed: set[str] = set()   # …and actively confirmed
        self.patterns_seen: set[str] = set()       # vuln classes ever surfaced
        self.patterns_confirmed: set[str] = set()  # vuln classes confirmed real
        # background worker drives autopilot (confirms safe candidates on its own)
        self._stop = threading.Event()
        threading.Thread(target=self._auto_loop, daemon=True).start()

    def _auto_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.autopilot_tick()
            except Exception:
                pass
            self._stop.wait(2.0)

    def stop(self) -> None:
        self._stop.set()

    # ---- ingest ----
    def add(self, t: Transaction) -> bool:
        auto = False
        with self.lock:
            self._autodetect(t)
            # scope guard also applies to what we *record*, not just what we send
            if self.cfg.lab and not self.cfg.in_scope(t.url):
                return False
            self.txns.append(t)
            self.seen_urls.add(t.url.split("?")[0])
            self._dirty = True
            self.last_ingest = time.time()
            # once we know the target, crawl it ONCE so the board fills itself
            if (self.cfg.lab and self.autopilot and not self._autocrawled
                    and self.session.sess is not None):
                self._autocrawled = True
                auto = True
        if auto:
            self.start_crawl()
        return True

    def _autodetect(self, t: Transaction) -> None:
        """Zero-config: learn the target + exploit server from the traffic so a
        beginner never has to know what LAB/EXPLOIT are. BSCP profile only."""
        if self.cfg.profile != "bscp":
            return
        host = urlparse(t.url).netloc            # keep original case
        # LAB = the web-security-academy.net host we're ACTUALLY browsing. Adopt it
        # whenever the configured lab is empty, a placeholder, or a stale host from
        # a previous session — labs get a fresh hostname every time, and a wrong
        # lab host would silently reject all real traffic via the scope guard.
        if host.lower().endswith("web-security-academy.net"):
            cur = (self.cfg.lab or "").lower()
            # adopt the real host only when the lab is unset or a placeholder — a
            # deliberately-set lab is left alone (in lab mode every academy host is
            # already in scope, so we never need to flip it and risk clobbering scope)
            if (not cur) or _is_placeholder(cur):
                self.cfg.lab = host
                if (not self.cfg.scope) or any(_is_placeholder(s) for s in self.cfg.scope):
                    self.cfg.scope = [host]
                self.ph = self.cfg.placeholders()
        # EXPLOIT = the exploit-server link embedded in the lab header
        if not self.cfg.exploit:
            m = _EXPLOIT_HOST_RE.search(t.resp_body or "") or _EXPLOIT_HOST_RE.search(t.url)
            if m:
                self.cfg.exploit = m.group(1)
                self.ph = self.cfg.placeholders()

    # ---- read ----
    def snapshot(self) -> dict:
        with self.lock:
            if self._dirty:
                self._cache = triage(self.current, self.txns, self.ph)
                # re-apply any confirmation verdicts to the freshly-built candidates
                for c in self._cache:
                    if c.cid in self.verdicts:
                        c.confirmed, c.confirm_note = self.verdicts[c.cid]
                    if c.cid in self.ready:
                        existing = {p.name for p in c.tailored}
                        c.tailored = [p for p in self.ready[c.cid] if p.name not in existing] + c.tailored
                    self.patterns_seen.add(c.vuln_class)   # learning log: met this pattern
                self._dirty = False
            cands = self._cache
            for c in cands:
                self.patterns_seen.add(c.vuln_class)
            return {
                "mode": self.cfg.mode,
                "profile": self.cfg.profile,
                "lab": self.cfg.lab,
                "exploit": self.cfg.exploit,
                "collab": self.cfg.collab,
                "stage": int(self.current),
                "stage_title": self.current.title,
                "txns": len(self.txns),
                "endpoints": len(self.seen_urls),
                "scope": ", ".join(self.cfg.scope) or self.cfg.lab or "(none)",
                "probes": len(self.session.probe_log),
                "crawling": self._crawling,
                "crawl_pages": self.crawl_pages,
                "last_ingest_ago": round(time.time() - self.last_ingest, 1) if self.last_ingest else None,
                "can_advance": self.current != Stage.EXFIL,
                "next_stage": int(self.current) + 1 if self.current != Stage.EXFIL else None,
                "next_title": Stage(int(self.current) + 1).title if self.current != Stage.EXFIL else None,
                "needs_setup": not self.cfg.collab,
                "autopilot": self.autopilot,
                "auto_status": self.auto_status,
                "next_action": self._next_action(cands),
                "learning": {
                    "seen": sorted(self.patterns_seen),
                    "confirmed": sorted(self.patterns_confirmed),
                    "total": TEACH.count(),
                },
                "candidates": [self._cand_json(c) for c in cands],
            }

    # plain-English "where do I put this payload"
    _WHERE = {
        "sql-injection": "Burp Repeater (send the request there, paste into the URL, Send)",
        "reflected-stored-xss": "the exploit server body, then Deliver to victim",
        "dom-xss": "your browser address bar (test on yourself), then the exploit server for the victim",
        "ssrf": "Burp Repeater (replace the URL parameter, Send)",
        "os-command-injection": "Burp Repeater (paste into the parameter, Send), then check Collaborator",
        "xxe": "Burp Repeater (replace the XML body, Send)",
        "path-traversal": "Burp Repeater (paste into the file parameter, Send)",
    }

    def agents_report(self) -> dict:
        """Run the BSCP stage coordinator over the current traffic and return a
        goal-oriented kill-chain: one actionable lead + action plan per stage.
        Powers the dashboard's kill-chain panel (GET /api/agents)."""
        coord = ExamCoordinator()
        results = coord.run(self.txns, self.ph, gate_fn=lambda r: True)  # show all 3
        stages = []
        for r in results:
            stages.append({
                "stage": int(r.stage),
                "name": r.stage.name.title(),
                "goal": r.goal,
                "solved": r.solved,
                "lead_class": r.lead.vuln_class if r.lead else "",
                "lead_title": r.lead.title if r.lead else "",
                "what": r.what_is,
                "next": r.next_step,
                "payload": r.top_payload,
                "confidence": r.confidence,
                "alternatives": r.alternatives,
                "note": r.note,
            })
        done = sum(1 for s in stages if s["solved"])
        return {"stages": stages, "solved": done, "total": 3,
                "current": int(self.current)}

    def activity_feed(self, limit: int = 24) -> dict:
        """Recent probes the agents fired — the live 'what's being tested now'
        feed. Reads the probe audit log and labels each by what it was testing."""
        recs = self.session.probe_log[-limit:]
        import time as _t
        items = []
        for r in reversed(recs):
            items.append({
                "time": _t.strftime("%H:%M:%S", _t.localtime(r.ts)),
                "method": r.method, "status": r.status,
                "note": r.note or "", "url": r.url,
            })
        return {"items": items, "total": len(self.session.probe_log)}

    def squad_report(self) -> dict:
        """Run the per-stage specialist-agent squad over current traffic. Only
        the stage's own vuln-class agents are brought up — Stage 1's 10, Stage
        2's 8, Stage 3's 8. Powers the dashboard's squad panel (GET /api/squad)."""
        from .squad import SquadCoordinator
        coord = SquadCoordinator()
        reports = coord.run(self.txns, self.ph, gate_fn=lambda r: True)
        snap = coord.snapshot(reports)
        done = sum(1 for s in snap if s["solved"])
        return {"stages": snap, "solved": done, "total": 3,
                "current": int(self.current)}

    def _next_action(self, cands: list) -> dict | None:
        if not self.txns:
            return {"headline": "Open the lab in Burp's browser once",
                    "detail": "Just load the lab's home page in Burp's browser. As soon as "
                              "the tool sees it, it auto-crawls the site for you — you don't "
                              "have to click around. (Or hit '🕷 Crawl target'.)",
                    "payload": "", "where": "", "cid": ""}
        if not cands:
            return {"headline": "Keep browsing — nothing spotted yet for this stage",
                    "detail": "Visit more of the site (log in, use every feature). "
                              "The more you browse, the more the tool can find.",
                    "payload": "", "where": "", "cid": ""}
        from . import playbook as PB
        ranked = sorted(cands, key=lambda c: c.score, reverse=True)
        # 1) a confirmed finding -> give the step-by-step plan + ONE payload
        for c in ranked:
            if c.confirmed:
                pb = PB.build(c, self.cfg)
                if pb:
                    return {
                        "headline": f"✅ {c.title} is real — follow these steps",
                        "detail": pb.get("note", T.next_step(c.vuln_class)),
                        "steps": pb["steps"],
                        "payload": pb["recommended"]["body"],
                        "payload_name": pb["recommended"]["name"],
                        "terms": pb.get("terms", {}),
                        "stage_hint": pb.get("stage_hint"),
                        "cid": c.cid, "title": c.title,
                    }
                return {
                    "headline": f"✅ {c.title} is real — open its card below",
                    "detail": T.next_step(c.vuln_class),
                    "steps": [], "payload": "", "cid": c.cid, "title": c.title,
                }
        # 2) nothing confirmed yet -> confirm the top candidate (autopilot may be doing this)
        top = ranked[0]
        auto = self.autopilot and top.vuln_class in _AUTO_CONFIRMABLE
        return {
            "headline": (f"Checking {top.title}…" if auto
                         else f"Let's check: is {top.title} real?"),
            "detail": (T.what_is(top.vuln_class) + "  "
                       + ("The tool is testing this for you automatically — wait a few seconds."
                          if auto else "Click the ⚡ Confirm button on its card below.")),
            "steps": [], "payload": "", "cid": top.cid, "title": top.title,
        }

    def _cand_json(self, c) -> dict:
        return {
            "cid": c.cid, "title": c.title, "vuln_class": c.vuln_class,
            "confidence": str(c.confidence), "score": c.score,
            "location": c.location, "evidence": c.evidence,
            "detect": c.detect_hint, "play": c.play_hint,
            "confirmed": c.confirmed, "confirm_note": c.confirm_note,
            "param": c.param, "target_url": c.target_url,
            "tailored": [{"name": p.name, "body": p.body, "kind": p.kind} for p in c.tailored],
            "payloads": [{"name": p.name, "body": p.body, "kind": p.kind} for p in c.payloads],
            "labs": c.labs,
            "teach": TEACH.teach(c.vuln_class),
            "show_exploit": self.cfg.mode == "lab",
        }

    # ---- gate ----
    def proceed(self) -> dict:
        with self.lock:
            if self.current != Stage.EXFIL:
                self.current = Stage(int(self.current) + 1)
                self._dirty = True
        return self.snapshot()

    def set_stage(self, n: int) -> dict:
        with self.lock:
            self.current = Stage(n)
            self._dirty = True
        return self.snapshot()

    def reset(self) -> dict:
        with self.lock:
            self.txns.clear()
            self.seen_urls.clear()
            self.verdicts.clear()
            self.current = Stage.FOOTHOLD
            self._dirty = True
        return self.snapshot()

    def report_md(self) -> str:
        from . import report
        from .models import StageResult
        results = {}
        for stage in (Stage.FOOTHOLD, Stage.PRIVESC, Stage.EXFIL):
            cands = triage(stage, self.txns, self.ph)
            for c in cands:
                if c.cid in self.verdicts:
                    c.confirmed, c.confirm_note = self.verdicts[c.cid]
                if c.cid in self.ready:
                    c.tailored = self.ready[c.cid] + c.tailored
            results[stage] = StageResult(stage=stage, candidates=cands)
        return report.markdown(results, self.cfg.lab, self.cfg.mode,
                               probe_log=self.session.probe_log,
                               learning={"seen": sorted(self.patterns_seen),
                                         "confirmed": sorted(self.patterns_confirmed),
                                         "total": TEACH.count()},
                               cfg=self.cfg)

    def audit_log(self) -> str:
        return "\n".join(r.line() for r in self.session.probe_log) or "(no probes fired yet)"

    def setup(self, d: dict) -> dict:
        """Browser setup wizard writes the Collaborator (and optional overrides)."""
        with self.lock:
            from .config import _host
            if d.get("collab"):
                self.cfg.collab = _host(d["collab"])
            if d.get("lab"):
                # accept one OR several hosts (comma / space separated) so you can
                # span two boxes at once; the first is the primary lab for display
                hosts = [_host(x) for x in str(d["lab"]).replace(",", " ").split()]
                hosts = [h for h in hosts if h]
                if hosts:
                    self.cfg.lab = hosts[0]
                    self.cfg.scope = hosts
            if d.get("exploit"):
                self.cfg.exploit = _host(d["exploit"])
            self.ph = self.cfg.placeholders()
            self._dirty = True
        try:
            self.cfg.save()   # persist so they never redo it
        except Exception:
            pass
        return self.snapshot()

    # ---- auto-crawl: discover endpoints without manual clicking ----
    def start_crawl(self, max_pages: int = 60) -> dict:
        if self._crawling:
            return {"ok": False, "err": "already crawling"}
        if not self.cfg.lab:
            return {"ok": False, "err": "no target yet — browse the lab once, then crawl"}
        if self.session.sess is None:
            return {"ok": False, "err": "no live session (requests not installed)"}
        self._crawling = True
        self.crawl_pages = 0
        threading.Thread(target=self._crawl_worker, args=(max_pages,), daemon=True).start()
        return {"ok": True, "started": True}

    def _crawl_worker(self, max_pages: int) -> None:
        from urllib.parse import urljoin, urlparse
        # quote-optional: PortSwigger writes <script src=/resources/js/x.js>
        # unquoted, so a quoted-only regex never fetches the JS that holds the
        # DOM-XSS sink. Capture quoted "…"/'…' and bare src/href values alike.
        href = re.compile(r'(?:href|src|action)=(?:"([^"#]+)"|\'([^\'#]+)\'|([^\s>#]+))', re.I)
        try:
            # start from the scheme+host we've actually been seeing (https for real
            # labs); fall back to https://<lab>/ if we have no traffic yet
            start = f"https://{self.cfg.lab}/"
            cookie = ""
            for t in reversed(self.txns):
                pr = urlparse(t.url)
                if pr.netloc and start == f"https://{self.cfg.lab}/":
                    start = f"{pr.scheme}://{pr.netloc}/"
                if t.req_headers.get("Cookie") and not cookie:
                    cookie = t.req_headers["Cookie"]
            origin = urlparse(start).netloc
            seen: set[str] = set()
            queue = [start]
            inject_points: list = []
            self._inject_seen = set()
            while queue and self.crawl_pages < max_pages:
                url = queue.pop(0)
                if url in seen:
                    continue
                seen.add(url)
                try:
                    txn = self.session.fetch("GET", url,
                                             headers={"Cookie": cookie} if cookie else None,
                                             note="auto-crawl")
                except Exception:
                    continue
                if txn is None:
                    continue
                self.crawl_pages += 1
                self.add(txn)
                ct = txn.header("content-type") or ""
                if "html" not in ct:
                    continue
                body = txn.resp_body or ""
                # collect injection points on this page (forms + param-bearing links)
                for ip in self._inputs_on_page(url, body):
                    key = (ip[0], ip[1], ip[2])
                    if key not in self._inject_seen:
                        self._inject_seen.add(key)
                        inject_points.append(ip)
                for g in href.findall(body):
                    h = next((x for x in g if x), "")   # quote-optional tuple -> value
                    if not h:
                        continue
                    nxt = urljoin(url, h)
                    if urlparse(nxt).netloc == origin and nxt not in seen and nxt not in queue:
                        # skip logout / destructive links while crawling
                        if re.search(r"logout|signout|delete|/admin/delete", nxt, re.I):
                            continue
                        queue.append(nxt)
            # ---- content discovery: gobuster-style path sweep ----
            self._content_discovery(cookie)
            # ---- active probe pass: fire safe canaries into every input ----
            self._active_probe(inject_points, cookie)
            # ---- stored-XSS pass: re-fetch content pages so a canary POSTed to
            # a comment/form now shows up where it's rendered (stored reflection) ----
            self._refetch_content_pages(seen, cookie)
        finally:
            self._crawling = False

    def _refetch_content_pages(self, seen, cookie, limit: int = 12):
        """After probing, re-GET content-view pages (posts, home, comments) so a
        canary stored via a form surfaces in the body -> stored-XSS detection."""
        hdr = {"Cookie": cookie} if cookie else None
        targets = [u for u in seen
                   if re.search(r"/post\b|/blog\b|/comment|/feedback|/$", u, re.I)][:limit]
        for u in targets:
            try:
                txn = self.session.fetch("GET", u, headers=hdr, note="stored-XSS re-check")
            except Exception:
                continue
            if txn is not None:
                self.add(txn)

    # a compact, BSCP-relevant path wordlist (not a 10k gobuster list — enough
    # to surface the admin panel, APIs, backups, VCS and debug endpoints that
    # the exam hides, without hammering the lab).
    _WORDLIST = [
        "admin", "administrator", "admin-panel", "adminpanel", "panel",
        "login", "logout", "register", "signup", "user", "users", "account",
        "my-account", "profile", "settings", "console", "manage", "management",
        "internal", "api", "api/v1", "api/v2", "graphql", "rest", "swagger",
        "swagger-ui", "api-docs", "openapi.json", "status", "health",
        "actuator", "actuator/health", "metrics", "debug", "test", "dev",
        "staging", "backup", "backups", "backup.zip", "backup.tar.gz",
        "backup.sql", "db.sql", "config", "config.php", ".env", ".git/HEAD",
        "robots.txt", "sitemap.xml", "server-status", "phpinfo.php",
        "cgi-bin", "uploads", "files", "download", "cms", "phpmyadmin",
        ".well-known/security.txt", "analytics", "cms/login",
    ]

    def _content_discovery(self, cookie, max_probes: int = 60):
        """Request a curated wordlist of common paths; keep the ones that exist
        (200) or are access-controlled (401/403) or error (500). The recon
        detector then flags admin panels, backups, VCS, APIs and debug pages."""
        base = f"https://{self.cfg.lab}"
        hdr = {"Cookie": cookie} if cookie else None
        for word in self._WORDLIST[:max_probes]:
            url = f"{base}/{word}"
            try:
                txn = self.session.fetch("GET", url, headers=hdr,
                                         note=f"content-discovery → /{word}")
            except Exception:
                continue
            if txn is None:
                continue
            if txn.status in (200, 401, 403, 500):
                self.add(txn)

    # input discovery + active probing -------------------------------------
    # attr value may be "quoted", 'quoted', or bare (PortSwigger omits quotes)
    _ATTR_ACTION = re.compile(r'action=(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', re.I)
    _ATTR_METHOD = re.compile(r'method=(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', re.I)
    _FIELD_RE = re.compile(
        r'<(?:input|textarea|select)\b[^>]*?\bname=(?:"([^"]+)"|\'([^\']+)\'|([^\s>]+))', re.I)
    _QUERY_LINK = re.compile(r'(?:href|action)=(?:"([^"]*\?[^"]+)"|\'([^\']*\?[^\']+)\'|([^\s>]*\?[^\s>]+))', re.I)

    @staticmethod
    def _first(groups):
        """pick the matched alternative from a quote-optional regex group tuple."""
        return next((g for g in groups if g), "")

    def _inputs_on_page(self, page_url, body):
        from urllib.parse import urljoin, urlparse, parse_qs
        out = []
        searchish = {"search", "q", "query", "s", "searchterm", "term", "keyword", "keywords"}

        # 1) HTML forms
        for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, re.I | re.S):
            attrs, inner = m.group(1), m.group(2)
            am = self._ATTR_ACTION.search(attrs)
            mm = self._ATTR_METHOD.search(attrs)
            action_val = self._first(am.groups()) if am else ""
            action = urljoin(page_url, action_val) if action_val else page_url
            method = (self._first(mm.groups()).upper() if mm else "GET")
            fields = [self._first(g) for g in self._FIELD_RE.findall(inner)]
            fields = [f for f in fields
                    if f and f.lower() not in ("csrf", "csrftoken", "_token",
                                                "authenticity_token", "nonce")]

            # Put search-like fields first
            fields.sort(key=lambda f: 0 if f.lower() in searchish else 1)

            for f in fields:
                extra = {g: "test" for g in fields if g != f}
                out.append((method, action, f, extra))

        # 2) query-string links (GET params already in the page)
        for g in self._QUERY_LINK.findall(body):
            link = self._first(g)
            if not link:
                continue
            full = urljoin(page_url, link)
            base, _, qs = full.partition("?")
            params = parse_qs(qs)
            for p in params:
                if p.lower() in ("csrf", "token", "nonce"):
                    continue
                extra = {k: (v[0] if v else "") for k, v in params.items() if k != p}
                out.append(("GET", base, p, extra))

        # Prioritise any search-like param across the whole list
        out.sort(key=lambda x: 0 if x[2].lower() in searchish else 1)
        return out[:50]

    def _active_probe(self, points, cookie, max_probes: int = 120):
        """Fire strong canaries into every input. Search-like parameters get
        multiple XSS canaries first. Purely detective — no exploit payloads."""
        from urllib.parse import urlencode
        import random
        hdr = {"Cookie": cookie} if cookie else None
        fired = 0
        searchish = {"search", "q", "query", "s", "searchterm", "term", "keyword", "keywords"}

        # Stronger XSS canaries (survive basic filters and trigger the detector)
        XSS_CANARIES = [
            "waptXssCanary99",
            "waptXss\"<svg/onload=1>",
            "waptXss'><img src=x onerror=1>",
            "waptXss\" onmouseover=1 ",
        ]

        for method, action, param, extra in points:
            if fired >= max_probes:
                break

            is_search = param.lower() in searchish
            short = action.split("//", 1)[-1].split("/", 1)[-1][:40]

            # 1) Always fire a clean reflection canary
            canaries = [("XSS/reflection", f"wapt{random.randrange(16**6):06x}")]

            # 2) For search-like params, also fire the stronger XSS canaries
            if is_search:
                for c in XSS_CANARIES:
                    canaries.append(("XSS/strong", c))

            # 3) Always try a SQL quote as well
            canaries.append(("SQLi/quote", f"wapt{random.randrange(16**6):06x}'"))

            for kind, canary in canaries:
                if fired >= max_probes:
                    break
                data = dict(extra)
                data[param] = canary
                note = f"{kind} probe → {param} @ /{short}"
                try:
                    if method == "POST":
                        txn = self.session.fetch(
                            "POST", action, headers=hdr,
                            body=urlencode(data), note=note
                        )
                    else:
                        q = urlencode(data)
                        txn = self.session.fetch(
                            "GET", f"{action}?{q}", headers=hdr, note=note
                        )
                except Exception:
                    continue
                if txn is not None:
                    fired += 1
                    self.add(txn)

        # Also force-probe the most common search entry points on the homepage
        self._force_search_probes(cookie)

        # Existing header probes
        self._probe_headers(cookie)

    def _force_search_probes(self, cookie):
        """Force common search entry points that many PortSwigger labs use.
        This guarantees the search XSS surface is exercised even if form
        parsing missed it."""
        if not self.cfg.lab:
            return
        hdr = {"Cookie": cookie} if cookie else None
        base = f"https://{self.cfg.lab}"
        canary = "waptForceSearch99"

        candidates = [
            f"{base}/?search={canary}",
            f"{base}/?SearchTerm={canary}",
            f"{base}/?q={canary}",
            f"{base}/search?search={canary}",
            f"{base}/search?SearchTerm={canary}",
        ]
        for url in candidates:
            try:
                txn = self.session.fetch("GET", url, headers=hdr,
                                        note="force-search probe")
                if txn is not None:
                    self.add(txn)
            except Exception:
                continue

    def _probe_headers(self, cookie):
        """Test the headers a WAPT actually tampers: X-Forwarded-Host (password
        reset poisoning / routing) and Origin (CORS). Canaries only — detective."""
        import random
        base = {"Cookie": cookie} if cookie else {}
        # pick a few pages worth testing headers on: home + any reset/forgot/account
        pages = []
        for t in self.txns:
            low = t.url.lower()
            if t.url.rstrip("/").endswith(self.cfg.lab) or any(
                    k in low for k in ("forgot", "reset", "password", "account", "login", "my-account")):
                if t.url not in pages:
                    pages.append(t.url)
        pages = pages[:6] or [f"https://{self.cfg.lab}/"]
        for url in pages:
            tag = f"{random.randrange(16**6):06x}"
            probes = [
                ({"X-Forwarded-Host": f"wapt{tag}.evil"}, f"host-header probe → X-Forwarded-Host @ {url}"),
                ({"Origin": f"https://wapt{tag}.evil"},    f"CORS probe → Origin @ {url}"),
            ]
            for extra, note in probes:
                h = dict(base); h.update(extra)
                try:
                    txn = self.session.fetch("GET", url, headers=h, note=note)
                except Exception:
                    continue
                if txn is not None:
                    self.add(txn)

    def toggle_autopilot(self, on: bool | None = None) -> dict:
        with self.lock:
            self.autopilot = (not self.autopilot) if on is None else bool(on)
            self.auto_status = "on" if self.autopilot else "off"
        return self.snapshot()

    def autopilot_tick(self) -> None:
        """One unit of autopilot work: confirm the top not-yet-tried candidate
        in the current stage. Called by a background worker."""
        if not self.autopilot or self.session.sess is None or not self.cfg.collab:
            return
        self.snapshot()  # refresh cache
        for c in sorted(self._cache, key=lambda x: x.score, reverse=True):
            if c.cid in self._auto_tried or c.confirmed:
                continue
            if c.vuln_class not in _AUTO_CONFIRMABLE:
                continue
            self._auto_tried.add(c.cid)
            try:
                self.confirm(c.cid)
            except Exception:
                pass
            return  # one per tick, rate-limited by the session

    def confirm(self, cid: str) -> dict:
        self.snapshot()  # ensure cache fresh
        cand = next((c for c in self._cache if c.cid == cid), None)
        if cand is None:
            return {"ok": False, "err": "unknown candidate (re-triaged?)"}
        if self.session.sess is None:
            return {"ok": False, "err": "no live session (requests not installed / triage-only)"}
        verdict = CF.confirm_candidate(self.session, cand, collab=self.cfg.collab)
        note = verdict.as_note()
        extra = None
        # on a confirmed SQLi, go one step further: build the ready UNION dump
        if verdict.ok and cand.vuln_class == "sql-injection":
            try:
                from .models import Payload
                txn = cand.signals[0].txn
                u = CF.build_union(self.session, txn, cand.param or "")
                if u:
                    extra = [Payload(f"READY dump — {u['note']}", u["payload"], "exploit")]
                    note += f"  ·  auto-built UNION ({u['columns']} cols)"
            except Exception:
                pass
        with self.lock:
            self.verdicts[cid] = (verdict.ok, note)
            cand.confirmed, cand.confirm_note = verdict.ok, note
            if verdict.ok:
                self.patterns_confirmed.add(cand.vuln_class)
            if extra:
                self.ready[cid] = extra
                cand.tailored = extra + cand.tailored
            self._dirty = True   # so score bump (confirmed) re-sorts the board
        return {"ok": True, "cid": cid, "confirmed": verdict.ok, "note": note,
                "ready": bool(extra)}


def _txn_from_payload(d: dict) -> Transaction:
    return Transaction(
        method=d.get("method", "GET"),
        url=d.get("url", ""),
        req_headers=d.get("req_headers", {}) or {},
        req_body=d.get("req_body", "") or "",
        status=d.get("status"),
        resp_headers=d.get("resp_headers", {}) or {},
        resp_body=d.get("resp_body", "") or "",
        meta={"source": d.get("source", "live")},
    )


def make_handler(state: LiveState):
    class Handler(BaseHTTPRequestHandler):
        # keep Burp's console / our terminal quiet
        def log_message(self, *a):  # noqa
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                return self._send(200, PAGE, "text/html; charset=utf-8")
            if self.path.startswith("/api/state"):
                return self._send(200, json.dumps(state.snapshot()))
            if self.path.startswith("/api/report"):
                md = state.report_md()
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Disposition",
                                 'attachment; filename="wapt-findings.md"')
                data = md.encode()
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if self.path.startswith("/api/log"):
                return self._send(200, state.audit_log(), "text/plain; charset=utf-8")
            if self.path.startswith("/api/agents"):
                return self._send(200, json.dumps(state.agents_report()))
            if self.path.startswith("/api/squad"):
                return self._send(200, json.dumps(state.squad_report()))
            if self.path.startswith("/api/activity"):
                return self._send(200, json.dumps(state.activity_feed()))
            return self._send(404, "{}")

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n) if n else b""
            if self.path == "/ingest":
                try:
                    d = json.loads(raw or b"{}")
                except Exception:
                    return self._send(400, '{"ok":false,"err":"bad json"}')
                # accept a single txn or a batch
                items = d if isinstance(d, list) else [d]
                added = 0
                for it in items:
                    if state.add(_txn_from_payload(it)):
                        added += 1
                return self._send(200, json.dumps({"ok": True, "added": added}))
            if self.path == "/api/proceed":
                return self._send(200, json.dumps(state.proceed()))
            if self.path == "/api/reset":
                return self._send(200, json.dumps(state.reset()))
            if self.path == "/api/setup":
                try:
                    d = json.loads(raw or b"{}")
                except Exception:
                    d = {}
                return self._send(200, json.dumps(state.setup(d)))
            if self.path == "/api/autopilot":
                try:
                    d = json.loads(raw or b"{}")
                except Exception:
                    d = {}
                return self._send(200, json.dumps(state.toggle_autopilot(d.get("on"))))
            if self.path == "/api/crawl":
                return self._send(200, json.dumps(state.start_crawl()))
            if self.path.startswith("/api/confirm/"):
                cid = self.path.rsplit("/", 1)[-1]
                return self._send(200, json.dumps(state.confirm(cid)))
            if self.path.startswith("/api/stage/"):
                try:
                    n = int(self.path.rsplit("/", 1)[-1])
                    return self._send(200, json.dumps(state.set_stage(n)))
                except Exception:
                    return self._send(400, "{}")
            return self._send(404, "{}")

    return Handler


def serve(cfg: Config, host: str = "127.0.0.1", port: int = 8777,
          seed: list[Transaction] | None = None, open_browser: bool = False) -> None:
    state = LiveState(cfg)   # starts its own autopilot worker
    if seed:
        for t in seed:
            state.add(t)
    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    url = f"http://{host}:{port}/"

    if open_browser:
        def _open():
            time.sleep(1.0)
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    print(f"""
WAPT live orchestrator  ·  mode={cfg.mode}  profile={cfg.profile}  autopilot={state.auto_status}
  target    : {cfg.lab or '(auto-detects when you browse the lab)'}
  dashboard : {url}
  ingest    : POST {url}ingest   (the Burp extension points here)

Open the dashboard, load burp/wapt_stream.py into Burp, and browse the target.
If the dashboard asks for your Collaborator address, paste it in. Ctrl-C to stop.
""")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        state.stop()
        print("\nstopped.")
