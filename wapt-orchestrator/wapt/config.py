"""Configuration: the three placeholders, scope, proxy, rate limit, mode.

Placeholders mirror the playbook's `replace ->` box:
    LAB     -> your target           (…web-security-academy.net)
    EXPLOIT -> your exploit server    (…exploit-server.net)
    COLLAB  -> your Collaborator      (…oastify.com)
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Config:
    # --- placeholders ---
    lab: str = ""
    exploit: str = ""
    collab: str = ""

    # --- run mode ---
    mode: str = "engagement"        # "engagement" (gated) | "lab" (auto-fire)
    profile: str = "bscp"           # "bscp" | "generic"

    # --- routing / safety ---
    proxy: str | None = "http://127.0.0.1:8080"   # Burp upstream; None to go direct
    verify_tls: bool = False        # Burp's CA breaks verification by default
    scope: list[str] = field(default_factory=list)  # allowed host substrings
    rate_per_sec: float = 3.0       # max requests/sec through the client
    timeout: float = 15.0
    user_agent: str = ("Mozilla/5.0 (WAPT-orchestrator; authorized-testing) "
                       "AppleWebKit/537.36")
    _loaded_from: str = ""

    def placeholders(self) -> dict[str, str]:
        return {"LAB": self.lab, "EXPLOIT": self.exploit, "COLLAB": self.collab}

    def in_scope(self, url: str) -> bool:
        host = urlparse(url).netloc.lower()
        if not host:
            return False
        # BSCP lab mode: never block a Web Security Academy lab host. Labs get a
        # fresh hostname each session and you may run two at once, so a stale or
        # placeholder scope must never silently drop real lab traffic.
        if self.mode == "lab" and self.profile == "bscp" \
                and host.endswith("web-security-academy.net"):
            return True
        if not self.scope:
            # default scope = the lab host, if we know it
            return (self.lab.lower() in host) if self.lab else True
        return any(s.lower() in host for s in self.scope)

    DEFAULT_FILE = "wapt.config"

    def save(self, path: str | None = None) -> str:
        path = path or self.DEFAULT_FILE
        lines = [
            "# WAPT orchestrator config — edit the three hosts for each lab.",
            "# bare hostnames only (no https://, no trailing /).",
            f"lab: {self.lab}",
            f"exploit: {self.exploit}",
            f"collab: {self.collab}",
            f"mode: {self.mode}",
            f"profile: {self.profile}",
            f"proxy: {self.proxy or ''}",
            f"scope: {','.join(self.scope)}",
            f"rate_per_sec: {self.rate_per_sec}",
        ]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return path

    @classmethod
    def from_args_and_env(cls, args) -> "Config":
        c = cls()
        # a saved config file loads first (so beginners don't re-type every time)
        cfg_file = getattr(args, "config", None) or (
            cls.DEFAULT_FILE if os.path.exists(cls.DEFAULT_FILE) else None)
        if cfg_file:
            _merge_file(c, cfg_file)
            c._loaded_from = cfg_file
        # env overrides the file (so secrets/infra can stay out of the file)
        c.lab = os.environ.get("WAPT_LAB", c.lab)
        c.exploit = os.environ.get("WAPT_EXPLOIT", c.exploit)
        c.collab = os.environ.get("WAPT_COLLAB", c.collab)
        for k in ("lab", "exploit", "collab", "mode", "profile",
                  "proxy", "rate_per_sec", "timeout"):
            v = getattr(args, k, None)
            if v is not None:
                setattr(c, k, v)
        if getattr(args, "no_proxy", False):
            c.proxy = None
        if getattr(args, "scope", None):
            c.scope = [s.strip() for s in args.scope.split(",") if s.strip()]
        # beginner-proofing: accept full URLs and strip to bare host
        c.lab = _host(c.lab)
        c.exploit = _host(c.exploit)
        c.collab = _host(c.collab)
        if not c.scope and c.lab:
            c.scope = [c.lab]
        return c


def _host(v: str) -> str:
    """'https://0aXX.web-security-academy.net/' -> '0aXX.web-security-academy.net'."""
    if not v:
        return v
    v = v.strip()
    v = re.sub(r"^https?://", "", v, flags=re.I)
    return v.split("/")[0].rstrip("/")


def _merge_file(c: Config, path: str) -> None:
    """Accept a minimal `key: value` file without a yaml dependency."""
    if not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip().strip('"\'')
        if not hasattr(c, k) or not v:
            continue
        cur = getattr(c, k)
        if isinstance(cur, bool):
            v = v.lower() in ("1", "true", "yes", "on")
        elif isinstance(cur, float):
            v = float(v)
        elif isinstance(cur, list):
            v = [x.strip() for x in v.split(",") if x.strip()]
        setattr(c, k, v)
