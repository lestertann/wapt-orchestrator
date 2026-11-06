"""Render the stage board to the terminal. No deps, works over SSH."""
from __future__ import annotations

from .models import Candidate, Confidence, Stage, StageResult

# ANSI, degrade gracefully if piped
import sys
_TTY = sys.stdout.isatty()


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _TTY else s


CONF_COLOR = {
    Confidence.CONFIRMED: "1;32", Confidence.HIGH: "32",
    Confidence.MEDIUM: "33", Confidence.LOW: "90",
}


def banner(stage: Stage) -> str:
    bar = "=" * 70
    return _c("1;36", f"\n{bar}\n  STAGE {int(stage)} — {stage.title}\n{bar}")


def board(result: StageResult, show_payloads: bool = True) -> str:
    out = [banner(result.stage)]
    cands = result.ranked()
    if not cands:
        out.append(_c("90", "  no candidates surfaced for this stage from the captured traffic."))
        return "\n".join(out)

    out.append(_c("1", f"\n  {len(cands)} candidate(s), ranked by confidence x impact:\n"))
    for i, c in enumerate(cands, 1):
        tick = _c("1;32", "[CONFIRMED]") if c.confirmed else ""
        conf = _c(CONF_COLOR.get(c.confidence, "0"), f"{c.confidence}".upper())
        out.append(f"  {_c('1', f'{i:>2}.')} {_c('1;37', c.title):<34} "
                   f"conf={conf:<12} score={c.score:<3} {tick}")
        out.append(f"      {_c('90','id')}      {c.cid}")
        out.append(f"      {_c('90','where')}   {c.location}")
        if c.evidence:
            out.append(f"      {_c('90','why')}     {c.evidence}")
        if c.confirm_note:
            out.append(f"      {_c('1;32','probe')}   {c.confirm_note}")
        if c.detect_hint:
            out.append(f"      {_c('36','detect')}  {c.detect_hint}")
        if c.play_hint:
            out.append(f"      {_c('35','play')}    {c.play_hint}")
        if show_payloads and c.tailored:
            out.append(f"      {_c('1;32','tailored')} (built from the real endpoint + param)")
            for p in c.tailored:
                kind = _c("31", "EXPLOIT") if p.kind == "exploit" else _c("32", "detect ")
                out.append(f"        {kind} {_c('1;37', p.name)}")
                for ln in p.body.splitlines():
                    out.append(f"          {_c('90','|')} {ln}")
        if show_payloads and c.payloads:
            out.append(f"      {_c('1','payloads')} (canonical reference)")
            for p in c.payloads:
                kind = _c("31", "EXPLOIT") if p.kind == "exploit" else _c("32", "detect ")
                out.append(f"        {kind} {_c('1;37', p.name)}")
                for ln in p.body.splitlines():
                    out.append(f"          {_c('90','|')} {ln}")
        if c.labs:
            out.append(f"      {_c('34','labs')}    (stuck? these PortSwigger labs are the guide)")
            for lab in c.labs:
                out.append(f"          {_c('34','·')} {lab}")
        out.append("")
    return "\n".join(out)


def summary_line(result: StageResult) -> str:
    cands = result.ranked()
    top = ", ".join(f"{c.title}({c.confidence})" for c in cands[:4])
    return _c("1", f"Stage {int(result.stage)}: {len(cands)} candidates. Top: {top or '—'}")
