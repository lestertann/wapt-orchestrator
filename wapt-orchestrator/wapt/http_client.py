"""A deliberately boring HTTP client: everything goes through Burp, stays in
scope, and is rate-limited. This is the only place in the engine allowed to
touch the network, so the safety rails live here and nowhere else.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from .config import Config
from .models import Transaction


@dataclass
class ProbeRecord:
    """One request the tool itself sent — the audit trail for engagement evidence."""
    ts: float
    method: str
    url: str
    status: int | None
    note: str = ""        # why we sent it (e.g. "sqli confirm: quote")

    def line(self) -> str:
        t = time.strftime("%H:%M:%S", time.localtime(self.ts))
        return f"{t}  {self.method:4} {self.status or '---'}  {self.url}" + (f"   # {self.note}" if self.note else "")

try:
    import requests
    import urllib3
    urllib3.disable_warnings()  # Burp CA -> noisy InsecureRequestWarning
except Exception:              # requests is optional for offline/triage-only use
    requests = None


class OutOfScope(Exception):
    pass


class _RateLimiter:
    def __init__(self, per_sec: float):
        self.min_interval = 1.0 / per_sec if per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = self.min_interval - (now - self._last)
            if delay > 0:
                time.sleep(delay)
            self._last = time.monotonic()


class ScopedSession:
    """Scope-guarded, rate-limited, Burp-routed wrapper around requests.

    fetch() returns a Transaction (never raises on HTTP status), or None if the
    request could not be made. Out-of-scope URLs raise OutOfScope — a hard stop,
    because sending engagement traffic off-scope is the one unrecoverable mistake.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.rl = _RateLimiter(cfg.rate_per_sec)
        self.count = 0
        self.probe_log: list[ProbeRecord] = []   # every request the tool sent
        if requests is None:
            self.sess = None
        else:
            self.sess = requests.Session()
            self.sess.headers["User-Agent"] = cfg.user_agent
            if cfg.proxy:
                self.sess.proxies = {"http": cfg.proxy, "https": cfg.proxy}
            self.sess.verify = cfg.verify_tls

    def fetch(self, method: str, url: str, *, headers=None, body=None,
              allow_redirects=True, note: str = "") -> Transaction | None:
        if not self.cfg.in_scope(url):
            self.probe_log.append(ProbeRecord(time.time(), method, url, None,
                                              "BLOCKED out-of-scope"))
            raise OutOfScope(url)
        if self.sess is None:
            raise RuntimeError("`requests` is not installed; triage-only mode. "
                               "pip install requests to enable live probes.")
        self.rl.wait()
        self.count += 1
        try:
            r = self.sess.request(
                method, url, headers=headers, data=body,
                allow_redirects=allow_redirects, timeout=self.cfg.timeout)
        except Exception as e:
            self.probe_log.append(ProbeRecord(time.time(), method, url, None, note or str(e)))
            return Transaction(method=method, url=url, req_headers=headers or {},
                               req_body=body or "", status=None,
                               meta={"error": str(e)})
        self.probe_log.append(ProbeRecord(time.time(), method, url, r.status_code, note))
        return Transaction(
            method=method, url=url,
            req_headers=dict(r.request.headers), req_body=body or "",
            status=r.status_code, resp_headers=dict(r.headers),
            resp_body=r.text, meta={"elapsed": r.elapsed.total_seconds()},
        )
