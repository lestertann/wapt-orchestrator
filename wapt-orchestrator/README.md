# WAPT Staged Orchestrator

A Burp-routed engine that turns the **BSCP three-stage playbook** into a driver:
feed it traffic (or a URL), it fingerprints the "signal → likely bug" indicators,
ranks the candidates for the current stage with **payloads pre-filled**, and
**gates** between Stage 1 → 2 → 3 so nothing runs ahead of you.

```
ingest ──▶ triage (identify IOCs) ──▶ confirm (safe probe) ──▶ BOARD ──▶ [gate: proceed?] ──▶ next stage
```

Stage 1 Foothold (anon → user) · Stage 2 Privesc (user → admin) · Stage 3 Exfil (admin → RCE → /home/carlos/secret)

---

## Easiest start (no command line) — for total beginners

1. **Double-click** `start-windows.bat` (Windows) or `start-mac-linux.command` (Mac).
   It installs what's needed, starts the engine, and opens the dashboard.
2. Load `burp/wapt_stream.py` into Burp once (see below), then **browse the target**.
3. The dashboard **auto-detects the target and exploit server**, asks you for your
   **Collaborator** address in a pop-up (paste from Burp), turns on **Autopilot**
   (auto-checks findings), and shows one big **⭐ DO THIS NOW** box telling you the
   single next thing to do — in plain words, with the text to copy and where to
   paste it.

See `START-HERE.txt` for the picture-book version. Everything below is the detail.

## Live mode (the way you actually use it) — no export, ever

Browse in Burp as normal; a thin extension streams every request/response to the
engine, which triages live and shows a **web dashboard** with a **Proceed to
Stage 2** button. Zero clicking, zero export.

```bash
# 0. first time? check your setup and save your hosts so you never retype them:
python3 run.py --check                                   # Python/requests/config check
python3 run.py --lab 0aXX.web-security-academy.net \
               --exploit exploit-0aYY.exploit-server.net \
               --collab abcd.oastify.com --save-config    # writes wapt.config
#    (full URLs are fine — https:// and trailing / are stripped automatically)

# 1. start the engine + dashboard (reads wapt.config; or use the env vars below)
python3 run.py --serve                 # prints http://127.0.0.1:8777/
#    env vars still work and override the file:
#    WAPT_LAB=… WAPT_EXPLOIT=… WAPT_COLLAB=… python3 run.py --serve

# 2. load the Burp extension (one time) — see burp/wapt_stream.py header:
#    Extender > Options > Python Environment > point at jython-standalone-2.7.x.jar
#    Extender > Extensions > Add > type: Python > select burp/wapt_stream.py

# 3. open http://127.0.0.1:8777/ and browse the target in Burp.
#    Candidates stream into Stage 1. Click "Proceed →" to move to Stage 2, etc.
```

Only **in-scope** traffic is streamed (set Burp's target scope). The extension is
a fixed ~90-line pipe — load it once and forget it; all logic stays in the Python
engine, so you tune detectors/payloads without ever touching Burp again.

> I couldn't run Burp in my build environment, so the extension itself is
> untested live — but the engine's ingest side is fully tested (`livetest.py`
> streams synthetic Burp traffic through the exact same path and asserts the
> whole stage flow). If the extension misbehaves on load, its Burp "Output" tab
> shows why.

You can preload a capture and then keep streaming:
`python3 run.py --serve --input yesterday.xml`.

---

## Offline / batch mode (triage a capture file)

```bash
pip install requests            # only needed for live probes / crawl

# triage a capture, stepping stage by stage (terminal gate between each):
python3 run.py --input samples/sample.burp

# or hand it a URL — it crawls through Burp, then triages:
python3 run.py --url https://$WAPT_LAB/

# prove it works with no file/network:
python3 selftest.py       # triage + gating logic
python3 livetest.py       # live server + streaming + stage advance
```

By default traffic routes through Burp at `http://127.0.0.1:8080` so everything
still lands in your Burp history. Use `--no-proxy` to go direct.

---

## What the engine does for you (not just lists bugs)

- **Active confirmation.** Each candidate has a **⚡ Confirm** button. It fires
  *safe* differential probes through your proxy — a single quote, a true/false
  boolean pair, a reflection canary, an OOB ping — and gives a verdict like
  *"CONFIRMED: boolean-based SQLi on `SearchTerm`"*. No destructive payloads; no
  20 rounds of hand-testing to work out which param is the real one. Confirmed
  candidates jump to the top of the board.
- **Finishes the SQLi.** When a SQL injection confirms, it auto-probes the
  **column count and text columns** and hands you the **ready UNION dump**
  (`' UNION SELECT NULL,username,NULL,password FROM users-- -`) — no manual
  column counting.
- **Beginner on-ramp.** The dashboard has a **Start guide**, a mini-glossary, and
  every card explains the bug in plain words with a concrete **"Next step"**.
  `python3 run.py --check` verifies your setup and tells you what to do next.
- **Findings export + audit log.** **⬇ Download findings** gives a Markdown
  report (confirmed first, with payloads). **🧾 Probe log** shows every request
  the tool itself sent, timestamped — your engagement evidence trail. The header
  always shows the active **scope** and **probe count**. (`--report file.md` in
  batch mode.)
- **Tailored payloads.** Alongside the canonical reference payloads, each
  candidate shows payloads **built from the real endpoint + parameter it was
  seen on** — so it says `/search_res?SearchTerm=...`, not a generic `?search=`.
  No hand-editing the param name or path.
- **False-positive suppression.** PortSwigger lab chrome (the `academyLabHeader`
  status socket, `/resources/labheader/*`), content IDs mistaken for role fields
  (a blog post's `"id":5`), and CSRF-token reflections are filtered out so the
  board shows real leads.

## How it maps to your playbook

Every **"identify — signal → likely bug"** row is an `IF signal THEN candidate`
rule → it's a **detector** in `wapt/detectors.py`.
Every topic's **Detect / Payloads / Labs** block → the hints, payload bank and
lab links in `wapt/templating.py`.

So each board entry gives you, per candidate:

- **why** — the evidence that fired (the IOC)
- **detect / play** — the one-liners from the playbook
- **payloads** — `detect` (safe probe) and `EXPLOIT` (held), placeholders already swapped
- **labs** — the matching PortSwigger labs, as your *"stuck? read this"* guide

Ranked by `confidence × impact` so the highest-value lead is on top.

---

## Input modes

| Source | Flag | Fidelity |
|---|---|---|
| Burp **XML export** (Proxy history → Save items) | `--input x.xml` | ★★★ perfect req/resp pairing — **use for real work** |
| **HAR** | `--input x.har` | ★★★ clean |
| Raw **`.burp` project** save file | `--input x.burp` | ★★ best-effort *carve* (see caveat) |
| Live **crawl** | `--url https://…` | depends on coverage |

> **`.burp` caveat.** The project save file is Burp's proprietary binary format;
> Burp needs its own internal index to pair requests with responses, and that
> index isn't something we can read back out. The orchestrator **carves** the
> plaintext HTTP blocks and pairs them by file order — good enough to drive
> triage for a quick look, **not authoritative**. For anything that matters,
> export HTTP history as XML. (On the 64 MB sample this still recovers ~4,000
> transactions and finds the real `roleid` leak, SQLi sinks, etc.)

---

## Modes & safety

- `--mode engagement` *(default)* — operator-gated. Identifies + confirms with
  **safe** probes + templates the exploit, but **never fires exploitation**.
  Scope-guarded, rate-limited. The right default for client WAPT.
- `--mode lab` — intended for PortSwigger labs you own: the exploit payloads are
  ready to auto-fire downstream.

Hard rails live in one place (`wapt/http_client.py`): **scope guard** (an
out-of-scope URL is a hard stop), **rate limit** (`--rate-per-sec`, default 3),
Burp upstream routing. Set `--scope host1,host2` or it defaults to the lab host.

> Authorized testing only. Keep the engine pointed at targets in your engagement
> scope (or labs you own).

---

## The gate

After each stage you get the board, then:

```
>>> Stage 1 done. Proceed to Stage 2 (Privilege escalation)?  [y/N/q]
```

`y` → re-runs the whole loop for the next stage. Anything else stops; resume with
`--start 2`. `--auto` runs 1→2→3 with no prompts (headless / lab grinding).

---

## Extending it

Add coverage by writing one function — that's the design goal:

```python
from wapt.detectors import detector
from wapt.models import Stage, Signal, Confidence as C

@detector(Stage.EXFIL)
def d_my_sink(txn, ctx):
    if "weird-param=" in txn.url:
        yield Signal("ssrf", "weird fetcher param", C.MEDIUM, txn.url, txn=txn)
```

Then add its payloads + labs under that vuln class in `wapt/templating.py`.

---

## Layout

```
run.py                 CLI entry  (--serve live | --input file | --url crawl)
selftest.py            hermetic triage + gating test (no network)
livetest.py            live server + streaming + stage-advance test
improvetest.py         FP-suppression + tailoring + active-confirm test (mock target)
v4test.py              config-normalize + auto-UNION + report + audit-log test
burp/wapt_stream.py    the thin Jython Burp extension (load this into Burp)
wapt/
  report.py            Markdown findings report (used by export + --report)
  models.py            Transaction / Signal / Candidate / Stage
  config.py            placeholders, scope, mode, proxy, rate
  http_client.py       scoped + rate-limited + Burp-routed session (safety rails)
  ingest.py            Burp-XML / HAR / .burp-carver / crawler
  detectors.py         the identify-table rules, per stage (+ FP suppression)
  templating.py        canonical payload bank + Detect/Play hints + lab links
  tailor.py            payloads built from the real captured endpoint + param
  confirm.py           active confirmation — safe differential probes + verdict
  triage.py            signals → ranked candidates
  engine.py            the staged loop + the gate (batch mode)
  live.py              live ingest server + stage state + /api/confirm
  dashboard.py         the localhost web UI (board, Confirm + Proceed buttons)
  reporting.py         the terminal board (batch mode)
  profiles.py          bscp / generic knobs
```

---

## Honest scope

Detection + confirmation automate well; **full auto-exploitation does not** — your
own playbook keeps saying *"always confirm live; column counts, ports and
Content-Length vary."* This engine is ~90% automated on **identify + confirm**
and **templates** the exploit for you to fire. That's deliberate, and it's the
professionally-correct default for client work.

---

## Making the tool keep improving itself

Two pieces (see `bench.py` and `autoimprove.py`):

- **`python3 bench.py`** — runs the tool against a catalog of **41 scenarios
  modeled on the PortSwigger Web Security Academy labs** (`labs.py`), named after
  the real labs and covering every vuln class. Scores detection %, confirmation %
  and false positives per topic, writing **`gap_report.md`**. No API key. Add
  scenarios to `labs.py` to raise the bar — each one becomes a target the loop
  will work to pass. (It can't drive the live labs — those are per-user and
  authenticated — so it reproduces each lab's *signal*; execution-only labs are
  scored on detection.)

- **`python3 autoimprove.py --iterations 5`** — the self-improvement loop. With
  your `ANTHROPIC_API_KEY` set, it repeatedly: benchmarks → finds the top gap →
  asks Claude to write a code patch → applies it to a backup-protected copy →
  re-runs the **full test suite + benchmark** → **keeps the change only if
  everything still passes AND the score improved, otherwise reverts** byte-for-
  byte. Every step is logged to `improve_log.md`. Set the model with
  `WAPT_IMPROVE_MODEL` (use one your key can access).

  Double-click `improve-windows.bat` / `improve-mac-linux.command` to run both.

**Honest limits:** the loop spends API tokens, and it can only improve what
`bench.py` measures — so the benchmark is the real lever. It won't invent novel
exploits, but it will close detection/confirmation gaps on its own, safely,
because nothing is kept unless the tests stay green.
