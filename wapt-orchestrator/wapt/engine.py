"""The orchestrator: ingest -> triage stage -> (safe confirm) -> board -> GATE
-> next stage. The gate is the thing you asked for: it stops after each stage
and waits for you to say 'proceed'.
"""
from __future__ import annotations

import sys

from . import reporting
from .config import Config
from .http_client import OutOfScope, ScopedSession
from .models import Candidate, Confidence, Stage, StageResult, Transaction
from .triage import triage


class Orchestrator:
    def __init__(self, cfg: Config, gate_fn=None):
        self.cfg = cfg
        self.session = ScopedSession(cfg)
        # gate_fn lets tests / headless runs inject answers; default = prompt
        self.gate_fn = gate_fn or self._prompt
        self.results: dict[Stage, StageResult] = {}

    # ---- the staged loop ---------------------------------------------------
    def run(self, txns: list[Transaction], start: Stage = Stage.FOOTHOLD,
            auto_proceed: bool = False) -> dict[Stage, StageResult]:
        ph = self.cfg.placeholders()
        print(self._header(len(txns)))

        for stage in (Stage.FOOTHOLD, Stage.PRIVESC, Stage.EXFIL):
            if stage < start:
                continue
            result = StageResult(stage=stage, candidates=triage(stage, txns, ph))
            # safe confirmation probes (live) only when we have a session + lab host
            if self.cfg.lab and self.session.sess is not None:
                self._confirm(result)
            result.finished = __import__("time").time()
            self.results[stage] = result

            print(reporting.board(result))
            print(reporting.summary_line(result))

            if stage == Stage.EXFIL:
                print("\n" + reporting._c("1;32", "All three stages triaged. "
                      "Fire the held exploit payloads in Burp to finish."))
                break

            if auto_proceed:
                continue
            if not self._gate(stage):
                print(reporting._c("33", f"\nStopped after Stage {int(stage)}. "
                      f"Re-run with --start {int(stage)+1} to resume."))
                break
        return self.results

    # ---- safe active confirmation -----------------------------------------
    def _confirm(self, result: StageResult) -> None:
        """Fire ONLY kind='detect' payloads' spirit: benign probes. Here we do the
        cheapest safe check per candidate — a scoped GET of the location — and
        mark confidence up if the signal re-appears live. Exploit payloads are
        never fired here (that's --mode lab's job, downstream)."""
        for c in result.ranked():
            probe = next((p for p in c.payloads if p.kind == "detect"), None)
            if not probe:
                continue
            # We don't blindly replay arbitrary probe strings; we just re-fetch the
            # candidate's own URL in-scope to confirm it's live and reachable.
            url = c.location.split("  ")[0].split(" ")[0]
            if not url.startswith("http"):
                continue
            try:
                txn = self.session.fetch("GET", url)
            except OutOfScope:
                c.confirm_note = "skipped (out of scope)"
                continue
            except Exception as e:
                c.confirm_note = f"probe error: {e}"
                continue
            if txn and txn.status and txn.status < 500:
                c.confirm_note = f"endpoint live ({txn.status}) — detect payload ready to fire"
            elif txn:
                c.confirm_note = f"endpoint returned {txn.status}"

    # ---- the gate ----------------------------------------------------------
    def _gate(self, stage: Stage) -> bool:
        nxt = Stage(int(stage) + 1)
        return self.gate_fn(stage, nxt)

    @staticmethod
    def _prompt(stage: Stage, nxt: Stage) -> bool:
        try:
            ans = input(reporting._c("1;36",
                f"\n>>> Stage {int(stage)} done. Proceed to Stage {int(nxt)} "
                f"({nxt.title})?  [y/N/q] ")).strip().lower()
        except EOFError:
            return False
        return ans in ("y", "yes", "proceed", "go")

    def _header(self, n: int) -> str:
        c = self.cfg
        return reporting._c("1", f"""
WAPT staged orchestrator  ·  mode={c.mode}  profile={c.profile}
  target   : {c.lab or '(unset — set WAPT_LAB)'}
  exploit  : {c.exploit or '(unset)'}
  collab   : {c.collab or '(unset)'}
  proxy    : {c.proxy or 'direct'}      scope: {', '.join(c.scope) or '(lab host)'}
  traffic  : {n} transaction(s) ingested
""")
