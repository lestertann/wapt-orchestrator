"""Triage: run a stage's detectors over all captured transactions, then group
the raw Signals into ranked Candidates (one per vuln class), attaching the
payloads, Detect/Play hints and PortSwigger lab links.
"""
from __future__ import annotations

from collections import defaultdict

from . import templating as T
from . import tailor as TL
from .detectors import detectors_for
from .models import Candidate, Confidence, Signal, Stage, Transaction

# nice titles for the board
TITLES = {
    "content-discovery": "Content discovery", "dom-xss": "DOM XSS",
    "web-message-xss": "Web-message XSS", "reflected-stored-xss": "Reflected / stored XSS",
    "cache-poisoning": "Web cache poisoning", "host-header": "Host-header attack",
    "request-smuggling": "HTTP request smuggling", "user-enum-brute": "User enum + brute force",
    "oauth-takeover": "OAuth takeover", "cswsh": "Cross-site WebSocket hijack",
    "sql-injection": "SQL injection", "idor-mass-assign": "IDOR / mass assignment",
    "csrf-takeover": "CSRF account takeover", "password-reset-logic": "Password-reset logic",
    "jwt-forge": "JWT forge", "cors-exfil": "CORS exfil", "api-graphql": "API / GraphQL",
    "client-side-proto-pollution": "Client-side prototype pollution",
    "path-traversal": "Path traversal / LFI", "ssti": "SSTI",
    "os-command-injection": "OS command injection", "ssrf": "SSRF",
    "xxe": "XXE", "file-upload-rce": "File upload -> RCE",
    "deserialization": "Insecure deserialization",
    "server-side-proto-pollution": "Server-side prototype pollution",
}


def triage(stage: Stage, txns: list[Transaction], ph: dict[str, str]) -> list[Candidate]:
    ctx: dict = {}  # reserved for cross-request facts (hosts, tokens seen, etc.)
    by_class: dict[str, list[Signal]] = defaultdict(list)

    for fn in detectors_for(stage):
        for txn in txns:
            try:
                for sig in fn(txn, ctx) or ():
                    by_class[sig.vuln_class].append(sig)
            except Exception:
                # one noisy txn must never sink the run
                continue

    candidates: list[Candidate] = []
    for cls, sigs in by_class.items():
        best = max(sigs, key=lambda s: int(s.confidence))
        # de-dupe locations for a tidy evidence list
        locs = []
        for s in sigs:
            if s.location not in locs:
                locs.append(s.location)
        best_txn = best.txn
        cand = Candidate(
            vuln_class=cls,
            title=TITLES.get(cls, cls),
            stage=stage,
            confidence=Confidence(best.confidence),
            location=best.location,
            evidence="; ".join(dict.fromkeys(s.evidence for s in sigs if s.evidence))[:300],
            detect_hint=T.hint(cls, "detect"),
            play_hint=T.hint(cls, "play"),
            payloads=T.render(cls, ph),
            tailored=TL.tailor(cls, best_txn, ph),
            labs=T.lab_links(cls),
            signals=sigs,
            target_url=best_txn.url if best_txn else "",
            method=best_txn.method if best_txn else "GET",
        )
        if cand.tailored and best_txn:
            _, _, params = TL.context(best_txn)
            cand.param = TL.pick_param(params)
        cand.evidence += f"   [{len(sigs)} signal(s), {len(locs)} location(s)]"
        candidates.append(cand)

    return sorted(candidates, key=lambda c: c.score, reverse=True)
