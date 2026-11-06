"""Agent layer — autonomous, goal-oriented BSCP stage solvers.

The BSCP exam is three sequential stages per app, each with a fixed objective.
This layer wraps the detection/triage engine in small agents that each OWN one
stage, know that stage's goal, hunt only that stage's bug classes, pick the
strongest lead, (optionally) run the safe confirm probe, and emit a plain
action plan. The ExamCoordinator chains the three agents toward the final goal
and gates between them — mirroring how you actually work the exam.

    coordinator ─▶ FootholdAgent ─▶ [gate] ─▶ PrivescAgent ─▶ [gate] ─▶ ExfilAgent
                   (get a session)            (reach /admin)          (read the secret)

Design goals: no new dependencies, reuses triage() + templating, and stays
honest — the agent *selects and plans*; a human (or lab-mode) fires the exploit.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import templating as T
from .models import Candidate, Stage, Transaction
from .triage import triage


# The fixed objective of each BSCP stage (from the official exam structure).
BSCP_GOALS: dict[Stage, str] = {
    Stage.FOOTHOLD: "Get a session as ANY user — steal a cookie via XSS/OOB, poison a "
                    "password reset, abuse the Host header, or brute/enumerate login.",
    Stage.PRIVESC:  "Reach the admin interface (/admin) as an administrator — role/JWT/"
                    "access-control tampering, SQLi for admin creds, or CSRF the admin.",
    Stage.EXFIL:    "Read /home/carlos/secret from the server and submit it — SSTI, path "
                    "traversal, XXE, SSRF, OS command injection, or deserialization.",
}


@dataclass
class AgentResult:
    """One agent's decision for its stage: the chosen lead + a plain action plan."""
    stage: Stage
    goal: str
    lead: Candidate | None
    what_is: str = ""
    next_step: str = ""
    top_payload: str = ""
    confidence: str = "none"
    alternatives: list[str] = field(default_factory=list)   # other classes seen, ranked
    note: str = ""

    @property
    def solved(self) -> bool:
        """The agent has an actionable lead with a payload + guidance (what a
        minimal-knowledge operator needs to proceed)."""
        return bool(self.lead and self.top_payload and self.what_is and self.next_step)

    def render(self) -> str:
        head = f"[{self.stage.name}] goal: {self.goal}"
        if not self.lead:
            return head + f"\n   (no lead — {self.note})"
        return (f"{head}\n"
                f"   lead     : {self.lead.title}  (confidence={self.confidence})\n"
                f"   what     : {self.what_is}\n"
                f"   do now   : {self.next_step}\n"
                f"   payload  : {self.top_payload.splitlines()[0][:100] if self.top_payload else '-'}\n"
                f"   also seen: {', '.join(self.alternatives) or '-'}")


class StageAgent:
    """Owns one exam stage. solve() triages only this stage's detectors, ranks,
    picks #1, optionally confirms, and returns an action plan toward the goal."""

    def __init__(self, stage: Stage):
        self.stage = stage
        self.goal = BSCP_GOALS[stage]

    def solve(self, txns: list[Transaction], ph: dict[str, str], confirm_fn=None) -> AgentResult:
        cands = triage(self.stage, txns, ph)
        if not cands:
            return AgentResult(self.stage, self.goal, None,
                               note="no lead for this stage — crawl more, or confirm you are "
                                    "actually on this stage (solve stages in order)")
        lead = cands[0]
        if confirm_fn is not None:
            try:
                confirm_fn(lead)   # may set lead.confirmed / lead.confirm_note
            except Exception:
                pass
        exploit = next((p for p in lead.payloads if p.kind == "exploit"), None)
        top = exploit or (lead.payloads[0] if lead.payloads else None)
        return AgentResult(
            stage=self.stage, goal=self.goal, lead=lead,
            what_is=T.what_is(lead.vuln_class),
            next_step=T.next_step(lead.vuln_class),
            top_payload=(top.body if top else ""),
            confidence=("confirmed" if lead.confirmed else str(lead.confidence)),
            alternatives=[c.title for c in cands[1:4]],
            note=f"{len(cands)} lead(s) for this stage",
        )


class ExamCoordinator:
    """Chains the three stage agents toward the BSCP objective, gating between
    stages (default gate: proceed only once the current stage has a solid lead)."""

    def __init__(self):
        self.agents = [StageAgent(s) for s in (Stage.FOOTHOLD, Stage.PRIVESC, Stage.EXFIL)]

    def run(self, txns: list[Transaction], ph: dict[str, str], gate_fn=None,
            confirm_fn=None) -> list[AgentResult]:
        results: list[AgentResult] = []
        for agent in self.agents:
            r = agent.solve(txns, ph, confirm_fn=confirm_fn)
            results.append(r)
            proceed = gate_fn(r) if gate_fn else r.solved
            if not proceed:
                break
        return results

    def report(self, results: list[AgentResult]) -> str:
        done = sum(1 for r in results if r.solved)
        lines = [r.render() for r in results]
        lines.append(f"\nstages with an actionable lead: {done}/3")
        return "\n".join(lines)
