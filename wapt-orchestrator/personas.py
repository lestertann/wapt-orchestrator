"""Three tester personas that 'use' the orchestrator and file feedback.

Each persona inspects the exact data the dashboard shows for a finding (the
candidate JSON, the Teach-Me lesson, the DO-THIS-NOW playbook card) through the
eyes of a specific user, and returns Findings. persona_test.py drives them over
one candidate per vuln class and aggregates the feedback so each improvement
round has a concrete to-do list — the same loop a real beta tester would create.

Personas
  A · "Aunty May"  — non-IT beginner (the stated audience). Can I follow this
                     without knowing the jargon? Is there ONE clear next thing?
  B · "Sam"        — BSCP student. Does each finding teach the PATTERN and give
                     me a lab to practise and a concrete next move?
  C · "Riz"        — senior pentester. Are the payloads correct, parameter-aware,
                     placeholder-free, and does automation cover what it safely can?
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Finding:
    persona: str
    severity: str   # "high" | "med" | "low"
    cls: str
    area: str
    msg: str


# classes whose exploitation is a single injectable string (so a beginner should
# get a copy-paste payload); the rest are procedural (steps only) and that's fine
_INJECTABLE = {"sql-injection", "reflected-stored-xss", "dom-xss", "web-message-xss",
               "ssti", "ssrf", "path-traversal", "os-command-injection", "xxe"}

# self-verifiable with a safe probe -> autopilot SHOULD be able to confirm these
_SELF_CONFIRMABLE = {"sql-injection", "reflected-stored-xss", "dom-xss",
                     "ssrf", "os-command-injection", "path-traversal",
                     "ssti", "cors-exfil"}

_PLACEHOLDER_LEAK = re.compile(r"YOUR-LAB|YOUR-COLLAB|<collab>|<lab>|\bLAB\b|\bCOLLAB\b|\bEXPLOIT\b")
_JARGON = ("Repeater", "Intruder", "Collaborator", "exploit server", "Burp")


def _quiz_ok(teach: dict) -> bool:
    q = (teach or {}).get("quiz") or {}
    opts = q.get("options") or []
    ans = q.get("answer")
    return bool(q.get("q")) and len(opts) >= 2 and isinstance(ans, int) and 0 <= ans < len(opts) \
        and bool(q.get("explain"))


def beginner(cand: dict, pb: dict | None, cfg_set: bool) -> list[Finding]:
    """Aunty May — needs plain language and one obvious action."""
    f = []
    cls = cand["vuln_class"]
    teach = cand.get("teach") or {}
    # 1) there must be a step-by-step card with a clear recommended action
    if pb is None:
        f.append(Finding("beginner", "high", cls, "playbook",
                         "no DO-THIS-NOW card — I'd be staring at payloads with no idea what to do"))
    else:
        if len(pb.get("steps", [])) < 3:
            f.append(Finding("beginner", "med", cls, "playbook",
                             "fewer than 3 steps — not hand-held enough for a non-IT user"))
        if not pb.get("note"):
            f.append(Finding("beginner", "low", cls, "playbook",
                             "no plain-English 'what this does' note on the card"))
        # the recommended payload (when there is one) should be copy-ready, no leaks
        body = (pb.get("recommended") or {}).get("body", "")
        if cfg_set and _PLACEHOLDER_LEAK.search(body or ""):
            f.append(Finding("beginner", "high", cls, "payload",
                             f"recommended payload still shows a placeholder: {body[:60]}"))
        # jargon in a step should be explained in plain English on the card
        joined = " ".join(pb.get("steps", [])) + " " + (pb.get("note") or "")
        terms = {k.lower() for k in (pb.get("terms") or {})}
        for j in _JARGON:
            if j.lower() in joined.lower() and j.lower() not in terms:
                f.append(Finding("beginner", "med", cls, "glossary",
                                 f"uses '{j}' with no plain-English definition on the card"))
                break
        # steps must be short enough to follow on a phone — one action each
        for s in pb.get("steps", []):
            if len(s) > 200:
                f.append(Finding("beginner", "low", cls, "readability",
                                 f"a step is {len(s)} chars — too long to follow in one go"))
                break
        # a non-IT user must never be dead-ended: the card needs a 'what if it
        # doesn't work' fail-safe so they know the next move
        blob = " ".join(pb.get("steps", [])).lower() + " " + (pb.get("note") or "").lower()
        if not any(k in blob for k in ("didn't work", "doesn't work", "if it fails",
                                       "if that fails", "if this exact", "if the page says",
                                       "if blocked", "if file", "if introspection", "if a waf")):
            f.append(Finding("beginner", "med", cls, "deadend",
                             "no 'if it doesn't work, do X' — a beginner gets stuck here"))
    # 2) teach lesson present and self-check valid
    if not teach.get("ioc") or not teach.get("why"):
        f.append(Finding("beginner", "med", cls, "teach",
                         "no 'what you saw / why it matters' — nothing to learn from"))
    if not _quiz_ok(teach):
        f.append(Finding("beginner", "low", cls, "teach", "self-check quiz malformed"))
    return f


def student(cand: dict, pb: dict | None, confirmed_note: str | None) -> list[Finding]:
    """Sam — wants the pattern, a lab to practise, and a concrete next move."""
    f = []
    cls = cand["vuln_class"]
    if not cand.get("labs"):
        f.append(Finding("student", "med", cls, "labs",
                         "no PortSwigger lab link to practise this pattern on"))
    teach = cand.get("teach") or {}
    if not teach.get("tell"):
        f.append(Finding("student", "med", cls, "teach",
                         "lesson doesn't say HOW to confirm it — can't build the reflex"))
    # the three-stage story: a learner should see which stage this is + the goal
    if pb is not None and not pb.get("stage_hint"):
        f.append(Finding("student", "low", cls, "stage",
                         "card doesn't say which of the 3 stages this is or what it unlocks"))
    # a confirmed finding must lead somewhere concrete
    if confirmed_note is not None:
        if "check" in confirmed_note.lower() and "collaborator" in confirmed_note.lower():
            pass  # OOB note is legitimately 'go poll Collaborator'
        elif pb is None or not (pb.get("recommended") or {}).get("body"):
            f.append(Finding("student", "high", cls, "next",
                             "confirmed but no concrete payload/next step to act on"))
    return f


def pentester(cand: dict, pb: dict | None, cfg_set: bool) -> list[Finding]:
    """Riz — correctness, parameter-awareness, coverage of safe automation."""
    f = []
    cls = cand["vuln_class"]
    tailored = cand.get("tailored") or []
    # injectable classes must ship parameter-aware payloads built from the request
    if cls in _INJECTABLE and cand.get("param") and not tailored:
        f.append(Finding("pentester", "high", cls, "tailored",
                         f"injectable class with a known param ({cand['param']}) but NO tailored payloads"))
    # no placeholder leakage anywhere in the payloads when the engagement is configured
    for p in tailored:
        if cfg_set and _PLACEHOLDER_LEAK.search(p.get("body", "")):
            f.append(Finding("pentester", "med", cls, "tailored",
                             f"placeholder leak in '{p['name'][:40]}': {p['body'][:50]}"))
            break
    # the tailored payload should actually reference the real param, not a default
    if cls in _INJECTABLE and cand.get("param") and tailored:
        p0 = tailored[0].get("body", "")
        if cand["param"] not in p0 and cand["param"] not in " ".join(t.get("name", "") for t in tailored):
            f.append(Finding("pentester", "low", cls, "tailored",
                             f"tailored payloads don't mention the real param {cand['param']}"))
    # automation coverage: a safely-confirmable class should be auto-confirmable
    if cls in _SELF_CONFIRMABLE and not cand.get("_auto_confirmable", True):
        f.append(Finding("pentester", "high", cls, "autopilot",
                         "safe self-verifying probe exists, but autopilot won't auto-confirm this class"))
    # XSS must offer a WAF/filter bypass for MORE than just the eval sink — real
    # targets filter 'fetch'/keywords in every context, not only JSON sinks
    if cls in ("reflected-stored-xss", "dom-xss"):
        waf_rows = [p for p in tailored if "waf" in p.get("name", "").lower()
                    or "bypass" in p.get("name", "").lower()]
        if len(waf_rows) < 2:
            f.append(Finding("pentester", "med", cls, "waf",
                             "only the eval-sink has a WAF bypass — HTML/attribute contexts need one too"))
    return f


def run_all(cand: dict, pb: dict | None, *, cfg_set: bool,
            confirmed_note: str | None = None) -> list[Finding]:
    return (beginner(cand, pb, cfg_set)
            + student(cand, pb, confirmed_note)
            + pentester(cand, pb, cfg_set))
