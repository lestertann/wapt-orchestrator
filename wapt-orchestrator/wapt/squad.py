"""Specialist-agent squad — one agent per vuln class, dispatched per stage.

The insight (from how the BSCP exam actually works): each stage only contains
a fixed *set* of vuln classes. So we don't throw every agent at every stage —
that would be noise. Instead each stage has a roster of specialist agents, and
the coordinator brings up ONLY the current stage's roster, runs them all at
once, picks the strongest lead, gates, and then brings up the next stage's set.

    Stage 1 roster                 Stage 2 roster              Stage 3 roster
    ┌───────────────┐              ┌───────────────┐          ┌───────────────┐
    │ XSS agent     │              │ SQLi agent    │          │ CMDi agent    │
    │ DOM-XSS agent │   ─[gate]─▶  │ JWT agent     │ ─[gate]─▶ │ SSTI agent    │
    │ host agent    │              │ IDOR agent    │          │ SSRF agent    │
    │ oauth agent   │              │ CSRF agent    │          │ XXE agent     │
    │ … (8 agents)  │              │ … (8 agents)  │          │ … (8 agents)  │
    └───────────────┘              └───────────────┘          └───────────────┘

Each agent owns exactly one vuln class: it hunts only that class across all the
captured traffic, lists the concrete injection points it would test, picks its
best payload, and (in live mode) fires its own safe confirm probe. Agents in a
stage run concurrently in a thread pool — that's where real HTTP probing
parallelism pays off.

No new dependencies: triage() + templating + tailor + confirm are reused as-is.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import templating as T
from . import tailor as TL
from . import teach
from .models import Candidate, Confidence, Stage, Transaction
from .triage import TITLES, triage


def reproduction(cand: Candidate) -> list[str]:
    """Numbered 'do it yourself' walkthrough for a finding — the teaching piece.
    Built from the vuln lesson + the real detect/exploit payloads tailored to
    this endpoint, so the user can reproduce the agent's work by hand."""
    lesson = teach.lesson(cand.vuln_class)
    where = cand.param or "the input"
    path = (cand.target_url or cand.location).split("?", 1)[0]
    steps: list[str] = []
    steps.append(f"Spot it: {lesson['ioc']}")
    steps.append(f"Why it works: {lesson['why']}")
    # the concrete detect probe (safe canary) tailored to this endpoint
    detect = next((p for p in cand.tailored if p.kind == "detect"), None) \
        or next((p for p in cand.payloads if p.kind == "detect"), None)
    if detect:
        steps.append(f"Confirm: send this to {where} @ {path} and watch the response "
                     f"({lesson['tell']}):\n       {detect.body.splitlines()[0]}")
    else:
        steps.append(f"Confirm: {lesson['tell']}")
    # the exploit payload(s)
    exploit = next((p for p in cand.tailored if p.kind == "exploit"), None) \
        or next((p for p in cand.payloads if p.kind == "exploit"), None)
    if exploit:
        steps.append(f"Exploit: once confirmed, fire this at {where}:\n       "
                     f"{exploit.body.splitlines()[0]}")
    if cand.labs:
        steps.append(f"Stuck? Mirror this PortSwigger lab: {cand.labs[0]}")
    return steps


# ----------------------------------------------------------------------------
# Roster: which specialist agents belong to which stage.
# A class appears under exactly the stage whose @detector emits it, so bringing
# up a stage's roster = exactly the agents that can possibly fire there.
# ----------------------------------------------------------------------------
STAGE_CLASSES: dict[Stage, list[str]] = {
    Stage.FOOTHOLD: [
        "reflected-stored-xss", "dom-xss", "web-message-xss",
        "host-header", "cache-poisoning", "request-smuggling",
        "oauth-takeover", "user-enum-brute", "cswsh", "content-discovery",
    ],
    Stage.PRIVESC: [
        "sql-injection", "jwt-forge", "idor-mass-assign", "csrf-takeover",
        "password-reset-logic", "cors-exfil", "api-graphql",
        "client-side-proto-pollution",
    ],
    Stage.EXFIL: [
        "os-command-injection", "ssti", "ssrf", "xxe", "path-traversal",
        "file-upload-rce", "deserialization", "server-side-proto-pollution",
    ],
}

# short, human agent names for the board / dashboard
AGENT_NAMES: dict[str, str] = {
    "reflected-stored-xss": "XSS agent", "dom-xss": "DOM-XSS agent",
    "web-message-xss": "web-message agent", "host-header": "host-header agent",
    "cache-poisoning": "cache agent", "request-smuggling": "smuggling agent",
    "oauth-takeover": "OAuth agent", "user-enum-brute": "auth-brute agent",
    "cswsh": "WebSocket agent", "content-discovery": "recon agent",
    "sql-injection": "SQLi agent", "jwt-forge": "JWT agent",
    "idor-mass-assign": "IDOR agent", "csrf-takeover": "CSRF agent",
    "password-reset-logic": "pw-reset agent", "cors-exfil": "CORS agent",
    "api-graphql": "API/GraphQL agent",
    "client-side-proto-pollution": "proto-pollution agent",
    "os-command-injection": "CMDi agent", "ssti": "SSTI agent",
    "ssrf": "SSRF agent", "xxe": "XXE agent",
    "path-traversal": "path-traversal agent", "file-upload-rce": "upload agent",
    "deserialization": "deser agent",
    "server-side-proto-pollution": "SSPP agent",
}

# which injection-point kinds each class cares about, for "what I'd test" lists
_SURFACE = {
    "sql-injection": ("query param", "cookie", "body field"),
    "reflected-stored-xss": ("query param", "body field"),
    "dom-xss": ("query param", "fragment"),
    "ssrf": ("url-valued param",), "path-traversal": ("file/path param",),
    "ssti": ("reflected param", "body field"), "xxe": ("xml body",),
    "os-command-injection": ("body field", "query param"),
    "jwt-forge": ("JWT cookie/header",), "idor-mass-assign": ("id param", "json field"),
    "cors-exfil": ("Origin header",), "host-header": ("Host header",),
}


def _short_where(url: str) -> str:
    """Collapse a monster URL to host-path + first param name, so the board
    shows '…/search_res?SearchTerm' not the whole proto-pollution payload."""
    if not url:
        return ""
    base, _, query = url.partition("?")
    try:
        path = base.split("//", 1)[-1].split("/", 1)
        shown = "/" + path[1] if len(path) > 1 else path[0]
    except Exception:
        shown = base
    if query:
        first = query.split("&", 1)[0].split("=", 1)[0]
        shown += f"?{first}…" if "&" in query else f"?{first}"
    return shown[:80]


def stage_of(vuln_class: str) -> Stage | None:
    for st, classes in STAGE_CLASSES.items():
        if vuln_class in classes:
            return st
    return None


# ----------------------------------------------------------------------------
# Findings
# ----------------------------------------------------------------------------
@dataclass
class VulnFinding:
    """One specialist agent's verdict on its class for the current stage."""
    vuln_class: str
    agent: str
    stage: Stage
    found: bool = False
    confidence: str = "none"
    where: str = ""
    param: str = ""
    targets: list[str] = field(default_factory=list)   # injection points it would test
    what_is: str = ""
    next_step: str = ""
    top_payload: str = ""
    confirmed: bool = False
    confirm_note: str = ""
    labs: list[str] = field(default_factory=list)
    repro: list[str] = field(default_factory=list)
    candidate: Candidate | None = None
    score: float = 0.0

    def render(self) -> str:
        if not self.found:
            tgt = f" (watched: {', '.join(self.targets)})" if self.targets else ""
            return f"   · {self.agent:<22} — nothing yet{tgt}"
        tick = "✓ CONFIRMED" if self.confirmed else self.confidence.upper()
        line = f"   ★ {self.agent:<22} — {tick}  @ {self.where}"
        if self.param:
            line += f"  (param {self.param})"
        return line


# ----------------------------------------------------------------------------
# The specialist agent — owns ONE vuln class
# ----------------------------------------------------------------------------
class VulnAgent:
    def __init__(self, vuln_class: str, stage: Stage):
        self.vuln_class = vuln_class
        self.stage = stage
        self.name = AGENT_NAMES.get(vuln_class, vuln_class)

    def _injection_points(self, txns: list[Transaction]) -> list[str]:
        """Concrete inputs this agent would probe — 'possible to SQLi it while
        crawling'. Built from the real captured endpoints + params, with the
        proto-pollution scanner noise filtered out so the list stays readable."""
        def _noise(name: str) -> bool:
            low = name.lower()
            return ("__proto__" in low or "prototype" in low
                    or "constructor" in low or len(name) > 40)

        pts: list[str] = []
        for t in txns:
            try:
                path, _, params = TL.context(t)
            except Exception:
                continue
            for p in params:
                if _noise(p):
                    continue
                tag = f"{p} @ {path}"
                if tag not in pts:
                    pts.append(tag)
        # cookies matter to sqli/jwt/deser
        if self.vuln_class in ("sql-injection", "jwt-forge", "deserialization"):
            for t in txns:
                ck = t.req_headers.get("Cookie") or t.req_headers.get("cookie") or ""
                for part in ck.split(";"):
                    name = part.split("=", 1)[0].strip()
                    if name and f"cookie:{name}" not in pts:
                        pts.append(f"cookie:{name}")
        return pts[:6]

    def hunt(self, stage_candidates: dict[str, Candidate], txns: list[Transaction],
             ph: dict[str, str], confirm_fn=None) -> VulnFinding:
        f = VulnFinding(vuln_class=self.vuln_class, agent=self.name, stage=self.stage)
        f.targets = self._injection_points(txns)
        cand = stage_candidates.get(self.vuln_class)
        if cand is None:
            return f  # nothing seen for this class — agent stands down
        f.found = True
        f.candidate = cand
        f.where = _short_where(cand.target_url or cand.location)
        f.param = cand.param
        f.what_is = T.what_is(self.vuln_class)
        f.next_step = T.next_step(self.vuln_class)
        f.labs = cand.labs
        exploit = next((p for p in cand.payloads if p.kind == "exploit"), None)
        top = exploit or (cand.payloads[0] if cand.payloads else None)
        f.top_payload = top.body if top else ""
        f.confidence = str(cand.confidence)
        f.repro = reproduction(cand)
        # live probe (optional) — this agent fires its own safe confirm
        if confirm_fn is not None:
            try:
                confirm_fn(cand)
            except Exception:
                pass
            f.confirmed = bool(cand.confirmed)
            f.confirm_note = cand.confirm_note
        f.score = cand.score
        return f


# ----------------------------------------------------------------------------
# Per-stage squad — only this stage's agents, run at once
# ----------------------------------------------------------------------------
@dataclass
class StageReport:
    stage: Stage
    findings: list[VulnFinding]

    @property
    def hits(self) -> list[VulnFinding]:
        return sorted([f for f in self.findings if f.found],
                      key=lambda x: x.score, reverse=True)

    @property
    def lead(self) -> VulnFinding | None:
        h = self.hits
        return h[0] if h else None

    @property
    def solved(self) -> bool:
        lead = self.lead
        return bool(lead and lead.top_payload and lead.what_is and lead.next_step)


class StageSquad:
    """Brings up exactly the agents for one stage and runs them concurrently."""

    def __init__(self, stage: Stage):
        self.stage = stage
        self.agents = [VulnAgent(c, stage) for c in STAGE_CLASSES[stage]]

    def run(self, txns: list[Transaction], ph: dict[str, str],
            confirm_fn=None, max_workers: int = 8) -> StageReport:
        # one triage for the stage → per-class candidate index the agents read
        cands = {c.vuln_class: c for c in triage(self.stage, txns, ph)}
        findings: list[VulnFinding] = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = {pool.submit(a.hunt, cands, txns, ph, confirm_fn): a
                    for a in self.agents}
            for fut in as_completed(futs):
                try:
                    findings.append(fut.result())
                except Exception:
                    a = futs[fut]
                    findings.append(VulnFinding(a.vuln_class, a.name, a.stage))
        # stable order: hits first (by score), then stood-down agents by roster
        order = {c: i for i, c in enumerate(STAGE_CLASSES[self.stage])}
        findings.sort(key=lambda f: (not f.found, -f.score, order.get(f.vuln_class, 99)))
        return StageReport(self.stage, findings)


# ----------------------------------------------------------------------------
# Coordinator — stage by stage, no overload
# ----------------------------------------------------------------------------
class SquadCoordinator:
    def __init__(self):
        self.squads = [StageSquad(s) for s in (Stage.FOOTHOLD, Stage.PRIVESC, Stage.EXFIL)]

    def run(self, txns: list[Transaction], ph: dict[str, str],
            gate_fn=None, confirm_fn=None) -> list[StageReport]:
        reports: list[StageReport] = []
        for squad in self.squads:
            rep = squad.run(txns, ph, confirm_fn=confirm_fn)
            reports.append(rep)
            proceed = gate_fn(rep) if gate_fn else rep.solved
            if not proceed:
                break
        return reports

    # machine-readable for the dashboard /api/squad
    def snapshot(self, reports: list[StageReport]) -> list[dict]:
        out = []
        for rep in reports:
            out.append({
                "stage": rep.stage.name,
                "stage_title": rep.stage.title,
                "solved": rep.solved,
                "lead": (rep.lead.agent if rep.lead else None),
                "agents": [
                    {
                        "agent": f.agent, "class": f.vuln_class,
                        "found": f.found, "confidence": f.confidence,
                        "confirmed": f.confirmed, "where": f.where,
                        "param": f.param, "targets": f.targets,
                        "payload": (f.top_payload.splitlines()[0][:160] if f.top_payload else ""),
                        "labs": f.labs,
                        "repro": f.repro,
                    } for f in rep.findings
                ],
            })
        return out

    def report(self, reports: list[StageReport]) -> str:
        lines = []
        for rep in reports:
            active = len(rep.findings)
            hits = len(rep.hits)
            lines.append("")
            lines.append("=" * 70)
            lines.append(f"  STAGE {int(rep.stage)} — {rep.stage.title}")
            lines.append(f"  roster: {active} agents up · {hits} reporting a lead")
            lines.append("=" * 70)
            for f in rep.findings:
                lines.append(f.render())
            hits = rep.hits
            if hits:
                lines.append("")
                lines.append("  RANKED ATTACK VECTORS (most promising first):")
                for i, f in enumerate(hits, 1):
                    tick = " ✓CONFIRMED" if f.confirmed else ""
                    lines.append(f"    #{i}  {f.agent} — {f.confidence}{tick}  @ {f.where}")
                lead = hits[0]
                lines.append("")
                lines.append(f"  >>> FOOTHOLD LEAD: {lead.agent} ({lead.confidence})")
                lines.append("      ── recreate it yourself ──")
                for n, step in enumerate(lead.repro, 1):
                    lines.append(f"      {n}. {step}")
            else:
                lines.append("  (no lead yet — crawl/probe more of this stage)")
        done = sum(1 for r in reports if r.solved)
        lines.append("")
        lines.append(f"stages with an actionable lead: {done}/3")
        return "\n".join(lines)
