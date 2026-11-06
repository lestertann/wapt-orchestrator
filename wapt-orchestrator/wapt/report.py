"""Findings export — a Markdown report of the board, confirmed first, with the
probe audit log appended. Used by the dashboard's Download button, by the live
/api/report endpoint, and by `run.py --report`.
"""
from __future__ import annotations

import time

from .models import Candidate, Stage


def markdown(stage_results: dict, lab: str, mode: str,
             probe_log=None, learning=None, cfg=None) -> str:
    out = []
    out.append(f"# WAPT findings — {lab or '(target)'}")
    out.append(f"_generated {time.strftime('%Y-%m-%d %H:%M:%S %Z')} · mode: {mode}_\n")

    if learning:
        seen, conf, tot = learning.get("seen", []), learning.get("confirmed", []), learning.get("total", 0)
        out.append(f"## 🎓 Patterns learned this session — seen {len(seen)}, confirmed {len(conf)} of {tot}\n")
        if conf:
            out.append("Confirmed (you proved these real): " + ", ".join(conf))
        if seen:
            out.append("Seen (spotted the pattern): " + ", ".join(seen))
        out.append("")

    total = sum(len(r.candidates) for r in stage_results.values())
    confirmed = sum(1 for r in stage_results.values() for c in r.candidates if c.confirmed)
    out.append(f"**{total} candidate(s)**, **{confirmed} confirmed**, across "
               f"{len(stage_results)} stage(s).\n")

    for stage in (Stage.FOOTHOLD, Stage.PRIVESC, Stage.EXFIL):
        res = stage_results.get(stage)
        if not res or not res.candidates:
            continue
        out.append(f"\n## Stage {int(stage)} — {stage.title}\n")
        for i, c in enumerate(res.ranked(), 1):
            tick = " ✅ CONFIRMED" if c.confirmed else ""
            out.append(f"### {i}. {c.title}  (`{c.confidence}`, score {c.score}){tick}")
            out.append(f"- **Where:** `{c.location}`")
            if c.param:
                out.append(f"- **Parameter:** `{c.param}`")
            if c.evidence:
                out.append(f"- **Why:** {c.evidence}")
            if c.confirm_note:
                out.append(f"- **Probe result:** {c.confirm_note}")
            if c.detect_hint:
                out.append(f"- **Detect:** {c.detect_hint}")
            # the actual step-by-step plan + ONE recommended payload (the DO-THIS-NOW card)
            if cfg is not None:
                try:
                    from . import playbook as PB
                    pb = PB.build(c, cfg)
                except Exception:
                    pb = None
                if pb:
                    if pb.get("stage_hint"):
                        out.append(f"- **Stage:** {pb['stage_hint']}")
                    rec = pb.get("recommended") or {}
                    out.append(f"- **Recommended action — {rec.get('name','')}:**")
                    if rec.get("body"):
                        out.append(f"      ```\n      {rec['body']}\n      ```")
                    if pb.get("steps"):
                        out.append("- **Steps:**")
                        for n, s in enumerate(pb["steps"], 1):
                            out.append(f"    {n}. {s}")
                    if pb.get("terms"):
                        out.append("- **Terms:** " + "; ".join(f"**{k}** — {v}"
                                   for k, v in pb["terms"].items()))
            if c.tailored:
                out.append("- **Tailored payloads:**")
                for p in c.tailored:
                    out.append(f"    - _{p.kind}_ `{p.name}`")
                    out.append(f"      ```\n      {p.body}\n      ```")
            if c.labs:
                out.append("- **Reference labs:** " + "; ".join(c.labs))
            out.append("")

    if probe_log:
        out.append("\n## Probe audit log\n")
        out.append("_Every request this tool sent, in order. Keep for engagement evidence._\n")
        out.append("```")
        for rec in probe_log:
            out.append(rec.line())
        out.append("```")

    return "\n".join(out)
