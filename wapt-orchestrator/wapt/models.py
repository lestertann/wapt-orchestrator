"""Core data models for the WAPT staged orchestrator.

Everything the engine passes around is one of these:
  - Transaction : a captured request/response pair (the raw material triage reads)
  - Signal      : a single "this looks like X" observation from one detector
  - Candidate   : a grouped, ranked finding for the stage board (signal + payloads)
  - StageResult : the output of running one stage
"""
from __future__ import annotations

import enum
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any


class Stage(enum.IntEnum):
    FOOTHOLD = 1       # anonymous -> any user
    PRIVESC = 2        # user -> admin
    EXFIL = 3          # admin -> RCE -> /home/carlos/secret

    @property
    def title(self) -> str:
        return {
            Stage.FOOTHOLD: "Foothold  (anonymous -> user)",
            Stage.PRIVESC: "Privilege escalation  (user -> admin)",
            Stage.EXFIL: "Exfiltration  (admin -> RCE -> secret)",
        }[self]


class Confidence(enum.IntEnum):
    LOW = 1            # weak passive hint, confirm by hand
    MEDIUM = 2         # a solid signal, worth a probe
    HIGH = 3           # strong / multiple corroborating signals
    CONFIRMED = 4      # an active safe probe came back positive

    def __str__(self) -> str:
        return self.name.lower()


# Rough "if I get this, how far does it take me" weighting, used only to
# rank the stage board. Higher = present it nearer the top.
IMPACT = {
    "sql-injection": 9,
    "jwt-forge": 8,
    "ssti": 9,
    "os-command-injection": 10,
    "deserialization": 10,
    "xxe": 8,
    "ssrf": 8,
    "file-upload-rce": 10,
    "path-traversal": 7,
    "server-side-proto-pollution": 9,
    "request-smuggling": 8,
    "oauth-takeover": 7,
    "cors-exfil": 6,
    "idor-mass-assign": 7,
    "csrf-takeover": 6,
    "password-reset-logic": 7,
    "cache-poisoning": 6,
    "host-header": 6,
    "cswsh": 5,
    "dom-xss": 5,
    "web-message-xss": 5,
    "reflected-stored-xss": 5,
    "user-enum-brute": 4,
    "client-side-proto-pollution": 5,
    "content-discovery": 6,
    "api-graphql": 6,
}


@dataclass
class Transaction:
    """One captured HTTP request/response pair."""
    method: str
    url: str
    req_headers: dict[str, str] = field(default_factory=dict)
    req_body: str = ""
    status: int | None = None
    resp_headers: dict[str, str] = field(default_factory=dict)
    resp_body: str = ""
    # free-form notes: set cookies, timing, where it came from, etc.
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def resp_headers_lower(self) -> dict[str, str]:
        return {k.lower(): v for k, v in self.resp_headers.items()}

    def header(self, name: str) -> str | None:
        return self.resp_headers_lower.get(name.lower())

    def __repr__(self) -> str:
        return f"<Txn {self.method} {self.url} -> {self.status}>"


@dataclass
class Signal:
    """A single observation emitted by a detector."""
    vuln_class: str                 # e.g. "sql-injection"
    label: str                      # human line, e.g. "TrackingId cookie present"
    confidence: Confidence
    location: str                   # where it was seen (url, param, header)
    evidence: str = ""              # the bytes/snippet that triggered it
    txn: Transaction | None = None


@dataclass
class Candidate:
    """A ranked board entry: what to try, where, and the ready payloads."""
    vuln_class: str
    title: str
    stage: Stage
    confidence: Confidence
    location: str
    evidence: str = ""
    detect_hint: str = ""           # the "Detect" line from the playbook
    play_hint: str = ""             # the "Play" line from the playbook
    payloads: list["Payload"] = field(default_factory=list)
    tailored: list["Payload"] = field(default_factory=list)   # built from real endpoint+param
    labs: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    confirmed: bool = False
    confirm_note: str = ""
    # observed context, used for tailoring + active confirmation
    target_url: str = ""         # the concrete URL the signal fired on
    param: str = ""              # the specific parameter in play, if any
    method: str = "GET"

    @property
    def score(self) -> float:
        base = int(self.confidence) * IMPACT.get(self.vuln_class, 5)
        return base + 1000 if self.confirmed else base   # confirmed sorts to the top

    @property
    def cid(self) -> str:
        raw = f"{self.vuln_class}|{self.location}"
        return hashlib.sha1(raw.encode()).hexdigest()[:8]


@dataclass
class Payload:
    """A copy-pasteable payload with placeholders already resolved."""
    name: str                       # what it does
    body: str                       # the payload itself (LAB/EXPLOIT/COLLAB filled in)
    kind: str = "detect"            # "detect" (safe probe) or "exploit" (held unless lab mode)


@dataclass
class StageResult:
    stage: Stage
    candidates: list[Candidate] = field(default_factory=list)
    started: float = field(default_factory=time.time)
    finished: float | None = None

    def ranked(self) -> list[Candidate]:
        return sorted(self.candidates, key=lambda c: c.score, reverse=True)
