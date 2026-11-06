#!/usr/bin/env python3
"""Agent-layer test — drives the ExamCoordinator over two BSCP-realistic apps
(modeled on the public practice-exam write-ups) and asserts each stage agent
picks the right lead, states its stage goal, and emits an action plan a
minimal-knowledge operator can follow.  Hermetic.  Run: python3 agenttest.py
"""
from wapt.agents import ExamCoordinator, BSCP_GOALS
from wapt.models import Stage, Transaction

PH = {"LAB": "0aXXlab.web-security-academy.net",
      "EXPLOIT": "ex.exploit-server.net", "COLLAB": "c.oastify.com"}
L = "https://0aXXlab.web-security-academy.net"


def T_(method, url, **kw):
    rh = {}
    for k, hk in (("cookie", "Cookie"), ("req_ct", "Content-Type"),
                  ("host", "Host"), ("origin", "Origin")):
        if kw.get(k):
            rh[hk] = kw[k]
    sh = {"Content-Type": kw.get("ct", "text/html")}
    sh.update(kw.get("resp_headers") or {})
    return Transaction(method, url, status=kw.get("status", 200), resp_headers=sh,
                       resp_body=kw.get("body", ""), req_headers=rh, req_body=kw.get("req_body", ""))


# App 1 (practice-exam shape): Host-header reset -> SQLi admin creds -> SSTI secret
APP1 = [
    T_("POST", f"{L}/forgot-password", host="0aXXlab.web-security-academy.net",
       req_ct="application/x-www-form-urlencoded", req_body="username=carlos",
       body="A reset link was sent to https://0aXXlab.web-security-academy.net/reset?token=abc"),
    T_("GET", f"{L}/filter?category=Gifts'", status=500,
       body="You have an error in your SQL syntax; SQLSTATE[42000]"),
    T_("GET", f"{L}/email-template-preview?message=hi"),
]
APP1_WANT = {Stage.FOOTHOLD: "host-header", Stage.PRIVESC: "sql-injection", Stage.EXFIL: "ssti"}

# App 2: reflected XSS cookie theft -> JWT alg:none -> OS command injection
APP2 = [
    T_("GET", f"{L}/?search=hackme", body="<h1>0 results for hackme</h1>"),
    T_("GET", f"{L}/my-account", cookie="session=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ3aWVuZXIifQ."),
    T_("GET", f"{L}/admin/image?imageFileName=1.jpg&ImgSize=120", ct="image/jpeg"),
]
APP2_WANT = {Stage.FOOTHOLD: "reflected-stored-xss", Stage.PRIVESC: "jwt-forge",
             Stage.EXFIL: "os-command-injection"}

APPS = [("App 1", APP1, APP1_WANT), ("App 2", APP2, APP2_WANT)]


def main():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("  PASS " if cond else "  FAIL ") + name)
        ok = ok and cond

    # goals are the real BSCP objectives
    check("foothold goal mentions a session", "session" in BSCP_GOALS[Stage.FOOTHOLD].lower())
    check("privesc goal mentions /admin", "/admin" in BSCP_GOALS[Stage.PRIVESC])
    check("exfil goal mentions /home/carlos/secret", "/home/carlos/secret" in BSCP_GOALS[Stage.EXFIL])

    for name, txns, want in APPS:
        print(f"\n### {name}")
        coord = ExamCoordinator()
        results = coord.run(txns, PH, gate_fn=lambda r: True)  # run all three regardless
        by_stage = {r.stage: r for r in results}
        print(coord.report(results))
        for stage, cls in want.items():
            r = by_stage.get(stage)
            check(f"{name} {stage.name}: agent picked {cls}",
                  bool(r and r.lead and r.lead.vuln_class == cls))
            check(f"{name} {stage.name}: emitted an action plan",
                  bool(r and r.solved))
        # the coordinator should mark all three stages actionable for a clean chain
        check(f"{name}: all 3 stages actionable", sum(r.solved for r in results) == 3)

    # gate behaviour: a gate that declines after stage 1 must stop the chain
    coord = ExamCoordinator()
    stopped = coord.run(APP1, PH, gate_fn=lambda r: r.stage == Stage.FOOTHOLD and False)
    check("gate declining after foothold stops the chain", len(stopped) == 1)

    # empty traffic: agent must degrade gracefully (no lead, not a crash)
    coord = ExamCoordinator()
    empty = coord.run([], PH, gate_fn=lambda r: True)
    check("empty capture -> foothold agent reports no lead (no crash)",
          empty and empty[0].lead is None and not empty[0].solved)

    print("\n" + ("ALL PASS ✅" if ok else "SOME FAILED ❌"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
