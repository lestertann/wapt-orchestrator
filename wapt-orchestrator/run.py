#!/usr/bin/env python3
"""WAPT staged orchestrator — CLI entry point.

Examples
--------
  # Triage a Burp project / XML / HAR, stepping stage by stage:
  WAPT_LAB=0aXX.web-security-academy.net \\
  WAPT_EXPLOIT=exploit-0aYY.exploit-server.net \\
  WAPT_COLLAB=abcd.oastify.com \\
  python3 run.py --input samples/traffic.burp

  # Just give it a URL and let it crawl through Burp first:
  python3 run.py --url https://0aXX.web-security-academy.net/ --lab 0aXX.web-security-academy.net

  # Lab mode, auto-advance through all three stages (no gate prompts):
  python3 run.py --input t.burp --mode lab --auto

  # Resume at Stage 2:
  python3 run.py --input t.burp --start 2
"""
from __future__ import annotations

import argparse
import sys

from wapt import ingest, profiles
from wapt.config import Config
from wapt.engine import Orchestrator
from wapt.http_client import ScopedSession
from wapt.models import Stage


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wapt-orchestrator",
        description="Burp-routed staged WAPT engine (BSCP three-stage playbook).",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--serve", action="store_true",
                   help="LIVE mode: run the dashboard + ingest server; stream from the "
                        "Burp extension (no export). Optionally preload with --input.")
    p.add_argument("--input", help="traffic file: .burp / .xml (Burp export) / .har")
    p.add_argument("--url", help="start URL to crawl through the proxy, then triage")
    p.add_argument("--check", action="store_true",
                   help="run a setup check (Python, requests, config) and print next steps")
    p.add_argument("--save-config", nargs="?", const="wapt.config", metavar="PATH",
                   help="save the current settings to a config file (default wapt.config) and exit")
    p.add_argument("--report", metavar="PATH", help="(batch mode) write a Markdown findings report")
    p.add_argument("--host", default="127.0.0.1", help="live server bind host")
    p.add_argument("--port", type=int, default=8777, help="live server port")
    p.add_argument("--open", action="store_true", dest="open_browser",
                   help="(live mode) open the dashboard in your browser automatically")

    p.add_argument("--lab", help="target host (…web-security-academy.net)  [or $WAPT_LAB]")
    p.add_argument("--exploit", help="exploit server host  [or $WAPT_EXPLOIT]")
    p.add_argument("--collab", help="Collaborator host  [or $WAPT_COLLAB]")

    p.add_argument("--mode", choices=["engagement", "lab"], default=None,
                   help="engagement=operator-gated (default), lab=auto-fire-ready")
    p.add_argument("--profile", choices=["bscp", "generic"], default=None,
                   help="bscp (default) or generic client WAPT")
    p.add_argument("--start", type=int, choices=[1, 2, 3], default=1,
                   help="stage to start/resume at")
    p.add_argument("--auto", action="store_true",
                   help="skip the between-stage gate prompts (runs 1->2->3)")

    p.add_argument("--proxy", default=None, help="upstream proxy (default http://127.0.0.1:8080)")
    p.add_argument("--no-proxy", action="store_true", help="go direct, bypass Burp")
    p.add_argument("--scope", help="comma-separated in-scope host substrings")
    p.add_argument("--rate-per-sec", dest="rate_per_sec", type=float, default=None)
    p.add_argument("--timeout", type=float, default=None)
    p.add_argument("--config", help="optional key: value config file")
    p.add_argument("--max-items", type=int, default=None,
                   help="cap transactions ingested (useful for big .burp files)")
    p.add_argument("--no-payloads", action="store_true", help="hide payloads on the board")
    p.add_argument("--agents", action="store_true",
                   help="run the autonomous BSCP stage agents (goal-oriented coordinator "
                        "report: one actionable lead + action plan per stage)")
    return p


def doctor(cfg) -> int:
    def ok(b): return "\033[32mOK\033[0m" if b else "\033[33m--\033[0m"
    try:
        import requests  # noqa
        have_req = True
    except Exception:
        have_req = False
    print(f"""
WAPT orchestrator — setup check
  [{ok(True)}] Python {sys.version.split()[0]}
  [{ok(have_req)}] requests {'installed' if have_req else 'MISSING  (pip install requests — needed for live probes/Confirm)'}
  [{ok(bool(cfg._loaded_from))}] config file {cfg._loaded_from or '(none — run with --save-config to create wapt.config)'}
  [{ok(bool(cfg.lab))}] target (LAB)     {cfg.lab or '(unset)'}
  [{ok(bool(cfg.exploit))}] exploit server   {cfg.exploit or '(unset)'}
  [{ok(bool(cfg.collab))}] Collaborator     {cfg.collab or '(unset)'}
  mode={cfg.mode}  proxy={cfg.proxy or 'direct'}  scope={','.join(cfg.scope) or '(lab host)'}
""")
    if not (cfg.lab and cfg.exploit and cfg.collab):
        print("Next: set your three lab hosts, then save them so you don't retype:\n"
              "  python run.py --lab <host> --exploit <host> --collab <host> --save-config\n"
              "Then just:  python run.py --serve")
    else:
        print("You're set. Start live mode:  python run.py --serve\n"
              "Then load burp/wapt_stream.py into Burp and browse the target.")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config.from_args_and_env(args)
    cfg = profiles.apply(cfg)

    if args.check:
        return doctor(cfg)
    if args.save_config is not None:
        path = cfg.save(args.save_config)
        print(f"saved config to {path}  (edit the three hosts per lab; env vars still override)")
        return 0
    if not (args.serve or args.input or args.url):
        print("Nothing to do. Try:\n"
              "  python run.py --check                 # setup check + next steps\n"
              "  python run.py --serve                 # live dashboard\n"
              "  python run.py --input traffic.burp    # triage a capture file", file=sys.stderr)
        return 2

    # ---- live mode ----
    if args.serve:
        from wapt import live
        seed = ingest.load_file(args.input, max_items=args.max_items) if args.input else None
        if seed:
            print(f"[*] preloaded {len(seed)} transaction(s) from {args.input}", file=sys.stderr)
        live.serve(cfg, host=args.host, port=args.port, seed=seed,
                   open_browser=args.open_browser)
        return 0

    if not cfg.lab:
        print("warning: no --lab/$WAPT_LAB set — scope defaults to permissive and "
              "live probes are skipped. Set it for real runs.", file=sys.stderr)

    # ---- ingest ----
    if args.input:
        print(f"[*] ingesting {args.input} …", file=sys.stderr)
        txns = ingest.load_file(args.input, max_items=args.max_items)
    else:
        print(f"[*] crawling {args.url} through {cfg.proxy or 'direct'} …", file=sys.stderr)
        sess = ScopedSession(cfg)
        txns = ingest.crawl(args.url, sess)
    print(f"[*] {len(txns)} transaction(s) ready.", file=sys.stderr)

    if not txns:
        print("no traffic to triage — check the input file or the crawl URL.", file=sys.stderr)
        return 2

    # ---- autonomous agent mode: goal-oriented per-stage coordinator ----
    if args.agents:
        from wapt.agents import ExamCoordinator
        ph = {"LAB": cfg.lab or "", "EXPLOIT": cfg.exploit or "", "COLLAB": cfg.collab or ""}
        coord = ExamCoordinator()
        results = coord.run(txns, ph, gate_fn=lambda r: True)
        print(coord.report(results))
        return 0

    orch = Orchestrator(cfg)
    orch.run(txns, start=Stage(args.start), auto_proceed=args.auto)

    if args.report:
        from wapt import report
        md = report.markdown(orch.results, cfg.lab, cfg.mode,
                             probe_log=orch.session.probe_log)
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"\n[*] findings report written to {args.report}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
