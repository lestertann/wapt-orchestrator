"""Profiles tune the engine to a target type.

bscp     : exam heuristics on — /home/carlos/secret is the goal, exploit-server
           and Collaborator exfil assumed, known sink shapes weighted up.
generic  : no lab assumptions; the same detectors, but confirmation is gentler
           and nothing BSCP-specific is presumed.

Right now a profile mainly flips a few knobs; the hook is here so you can grow
per-profile detector weighting without touching the engine.
"""
from __future__ import annotations

from .config import Config


def apply(cfg: Config) -> Config:
    if cfg.profile == "generic":
        cfg.rate_per_sec = min(cfg.rate_per_sec, 2.0)  # be politer off-lab
    return cfg


SECRET_PATH = "/home/carlos/secret"   # the BSCP goal, referenced by payloads
