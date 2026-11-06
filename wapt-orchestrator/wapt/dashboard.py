"""The localhost dashboard — one self-contained HTML string served at GET /.
Polls /api/state every 2s. No framework, no CDN; works offline on the tin.
Colours track the playbook: stage 1 teal, stage 2 amber, stage 3 red.
"""

PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAPT orchestrator</title>
<style>
  :root{
    --bg:#0c1016; --surface:#141a22; --surface2:#1a222c; --line:#232c37;
    --ink:#e6edf3; --soft:#9db0c0; --faint:#67788a;
    --s1:#39bda9; --s2:#e0a53a; --s3:#f0616b;
    --exploit:#f0616b; --detect:#39bda9;
    --mono:ui-monospace,"JetBrains Mono","Cascadia Code",Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.5}
  a{color:var(--s1)}
  .top{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--bg) 92%,transparent);
    backdrop-filter:blur(8px);border-bottom:1px solid var(--line);padding:.7rem 1rem}
  .top-row{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;max-width:1100px;margin:0 auto}
  .brand{font-family:var(--mono);font-weight:600;display:flex;align-items:center;gap:.5rem}
  .brand .dot{width:.6rem;height:.6rem;border-radius:2px;background:var(--s1);
    box-shadow:.4rem 0 0 var(--s2),.8rem 0 0 var(--s3);margin-right:.8rem}
  .pill{font-family:var(--mono);font-size:.72rem;color:var(--soft);background:var(--surface2);
    border:1px solid var(--line);border-radius:999px;padding:.15rem .6rem}
  .pill b{color:var(--ink)}
  .spacer{flex:1}
  .live{font-size:.72rem;color:var(--faint);font-family:var(--mono)}
  .live .on{color:var(--s1)}
  .auto{font-size:.78rem;color:var(--soft);display:flex;align-items:center;gap:.3rem;cursor:pointer}
  .auto input{accent-color:var(--s1)}
  .setup-wrap{position:fixed;inset:0;z-index:50;background:rgba(6,9,13,.82);
    display:flex;align-items:center;justify-content:center;padding:1rem}
  .setup-card{background:var(--surface);border:1px solid var(--line);border-radius:14px;
    max-width:30rem;padding:1.4rem 1.5rem}
  .setup-card h2{margin:.1rem 0 .5rem} .setup-card p{color:var(--soft);font-size:.9rem}
  .setup-card input{width:100%;margin:.5rem 0;padding:.6rem .7rem;border-radius:8px;
    border:1px solid var(--line);background:var(--surface2);color:var(--ink);font-family:var(--mono);font-size:.85rem}
  .setup-card details{margin:.3rem 0} .setup-card summary{font-size:.8rem;color:var(--faint);cursor:pointer}
  .setup-card button{background:var(--s1);color:#04110e;font-weight:700;border:0;border-radius:8px;
    padding:.6rem 1.1rem;font-size:.95rem;cursor:pointer;width:100%;margin-top:.3rem}
  .setup-skip{font-size:.74rem;color:var(--faint);margin-top:.6rem}
  .donow{background:linear-gradient(180deg,var(--surface2),var(--surface));
    border:1px solid var(--s1);border-radius:14px;padding:1rem 1.2rem;margin:.4rem 0 1rem;
    box-shadow:0 0 0 3px color-mix(in srgb,var(--s1) 15%,transparent)}
  .donow .dn-k{font-family:var(--mono);font-size:.68rem;letter-spacing:.08em;color:var(--s1);text-transform:uppercase}
  .donow h2{margin:.15rem 0 .35rem;font-size:1.12rem}
  .donow .dn-detail{color:var(--soft);font-size:.9rem;margin-bottom:.5rem}
  .donow .dn-where{font-size:.84rem;color:var(--ink)} .donow .dn-where b{color:var(--s2)}
  .donow pre{margin:.5rem 0 0;padding:.6rem;background:#0a0e13;color:#d7e0e8;border-radius:8px;
    font-family:var(--mono);font-size:.78rem;white-space:pre-wrap;word-break:break-word;position:relative}
  .donow .dn-copy{background:var(--s1);color:#04110e;border:0;border-radius:6px;font-weight:700;
    padding:.35rem .8rem;font-size:.8rem;cursor:pointer;margin-top:.5rem}
  .donow .dn-paylabel{font-size:.8rem;color:var(--s2);margin-top:.3rem;font-weight:600}
  .donow .dn-stage{font-size:.78rem;color:var(--accent);font-weight:600;margin-bottom:.35rem}
  .donow .dn-terms{margin-top:.6rem;font-size:.82rem}
  .donow .dn-terms summary{cursor:pointer;color:var(--accent);font-weight:600}
  .donow .dn-terms dt{font-family:var(--mono);color:var(--ink);margin-top:.4rem;font-weight:600}
  .donow .dn-terms dd{margin:.1rem 0 0;color:var(--soft)}
  .dn-steps{margin:.7rem 0 0;padding-left:1.3rem;counter-reset:dn}
  .dn-steps li{margin:.4rem 0;font-size:.92rem;color:var(--ink);line-height:1.5}
  .dn-steps li::marker{color:var(--s1);font-weight:700}
  .morebtn{background:none;border:1px dashed var(--line);color:var(--soft);border-radius:6px;
    padding:.3rem .7rem;font-size:.78rem;cursor:pointer;margin:.3rem 0}
  .stage .done{color:var(--s1);font-weight:700}
  main{max-width:1100px;margin:0 auto;padding:1rem}
  .stages{display:flex;gap:.5rem;margin:.2rem 0 1rem}
  .stage{flex:1;border:1px solid var(--line);border-radius:10px;padding:.6rem .8rem;background:var(--surface);
    opacity:.5;transition:.2s}
  .stage.active{opacity:1}
  .stage.s1.active{border-color:var(--s1);box-shadow:0 0 0 1px var(--s1) inset}
  .stage.s2.active{border-color:var(--s2);box-shadow:0 0 0 1px var(--s2) inset}
  .stage.s3.active{border-color:var(--s3);box-shadow:0 0 0 1px var(--s3) inset}
  .stage .n{font-family:var(--mono);font-size:.7rem;color:var(--faint)}
  .stage .t{font-weight:600;font-size:.9rem}
  .bar{display:flex;align-items:center;gap:.8rem;margin-bottom:1rem;flex-wrap:wrap}
  button{font-family:var(--sans);font-weight:600;border:0;border-radius:8px;padding:.55rem 1rem;
    cursor:pointer;font-size:.9rem}
  .proceed{background:var(--s1);color:#04110e}
  .proceed:disabled{background:var(--surface2);color:var(--faint);cursor:not-allowed}
  .ghost{background:var(--surface2);color:var(--soft);border:1px solid var(--line)}
  .count{font-family:var(--mono);font-size:.8rem;color:var(--soft)}
  .btnlink{text-decoration:none;display:inline-flex;align-items:center}
  .empty{color:var(--faint);text-align:center;padding:3rem 1rem;font-style:italic}
  .guide{background:var(--surface);border:1px solid var(--line);border-radius:10px;margin:.4rem 0 1rem;padding:.3rem .8rem}
  .guide summary{cursor:pointer;font-weight:600;color:var(--s1);padding:.4rem 0}
  .guide-body{font-size:.88rem;color:var(--soft);padding:.2rem 0 .6rem}
  .guide-body ol{margin:.4rem 0 .4rem 1.1rem;padding:0} .guide-body li{margin:.25rem 0}
  .guide-body b{color:var(--ink)} .guide .gloss{font-size:.82rem;color:var(--faint)}
  .plain{background:var(--surface2);border-left:3px solid var(--s1);border-radius:6px;
    padding:.5rem .7rem;margin:.2rem 0 .6rem;font-size:.86rem}
  .plain b{color:var(--s1)} .plain div{margin:.15rem 0}
  .opts{margin:.5rem 0} .opts summary{cursor:pointer;color:var(--soft);font-size:.82rem;
    padding:.3rem 0;user-select:none} .opts summary:hover{color:var(--ink)}
  .learnbar{background:var(--surface);border:1px solid var(--s2);border-radius:10px;
    padding:.6rem .9rem;margin:.2rem 0 1rem;font-size:.85rem}
  .learnbar .lb-h{color:var(--s2);font-weight:700;font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}
  .learnbar .chips{display:flex;flex-wrap:wrap;gap:.35rem;margin-top:.4rem}
  .chip2{font-size:.72rem;padding:.12rem .5rem;border-radius:999px;border:1px solid var(--line);
    background:var(--surface2);color:var(--faint)}
  .chip2.seen{color:var(--s2);border-color:var(--s2)}
  .chip2.conf{color:#04110e;background:var(--s1);border-color:var(--s1);font-weight:700}
  .teach{background:var(--surface2);border-left:3px solid var(--s2);border-radius:6px;
    padding:.6rem .8rem;margin:.3rem 0 .6rem;font-size:.86rem}
  .teach .t-k{font-family:var(--mono);font-size:.66rem;color:var(--s2);text-transform:uppercase;letter-spacing:.06em}
  .teach .t-row{margin:.35rem 0;color:var(--soft)} .teach .t-row b{color:var(--ink)}
  .quiz{margin-top:.55rem;border-top:1px dashed var(--line);padding-top:.5rem}
  .quiz .q{font-weight:600;color:var(--ink);font-size:.86rem;margin-bottom:.35rem}
  .quiz button{display:block;width:100%;text-align:left;background:var(--surface);border:1px solid var(--line);
    color:var(--ink);border-radius:6px;padding:.4rem .6rem;margin:.25rem 0;font-size:.84rem;cursor:pointer}
  .quiz button:hover{border-color:var(--s2)}
  .quiz button.right{background:#0f2b28;border-color:var(--s1);color:var(--s1);font-weight:700}
  .quiz button.wrong{background:#2c2411;border-color:var(--s2);color:var(--s2)}
  .quiz .explain{margin-top:.4rem;font-size:.82rem;color:var(--soft);font-style:italic}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:12px;margin-bottom:.8rem;overflow:hidden}
  .card h3{margin:0;padding:.7rem .9rem;display:flex;align-items:center;gap:.6rem;cursor:pointer;
    font-size:1rem;border-left:4px solid var(--faint)}
  .card.c-confirmed h3,.card.c-high h3{border-left-color:var(--s1)}
  .card.c-confirmed h3{border-left-width:5px}
  .card.c-medium h3{border-left-color:var(--s2)}
  .card.c-low h3{border-left-color:var(--faint)}
  .conf.confirmed{color:#04110e;background:var(--s1);border-color:var(--s1);font-weight:700}
  .confirm-row{display:flex;align-items:center;gap:.6rem;margin:.5rem 0}
  .confirmbtn{background:var(--surface2);color:var(--s1);border:1px solid var(--s1);
    padding:.3rem .7rem;border-radius:6px;font-size:.78rem}
  .confirmbtn:disabled{opacity:.5}
  .confirm-note{font-family:var(--mono);font-size:.76rem}
  .confirm-note.ok{color:var(--s1)} .confirm-note.no{color:var(--s2)}
  .rank{font-family:var(--mono);color:var(--faint);font-size:.8rem}
  .conf{font-family:var(--mono);font-size:.68rem;text-transform:uppercase;padding:.1rem .45rem;
    border-radius:4px;background:var(--surface2);border:1px solid var(--line)}
  .conf.confirmed,.conf.high{color:var(--s1)} .conf.medium{color:var(--s2)} .conf.low{color:var(--faint)}
  .score{margin-left:auto;font-family:var(--mono);font-size:.75rem;color:var(--faint)}
  .body{padding:0 .9rem .9rem;display:none}
  .card.open .body{display:block}
  .kv{font-size:.84rem;margin:.35rem 0}
  .kv .k{font-family:var(--mono);color:var(--faint);font-size:.72rem;margin-right:.5rem;text-transform:uppercase}
  .where{font-family:var(--mono);font-size:.78rem;color:var(--soft);word-break:break-all}
  .hint{font-size:.82rem;color:var(--soft);margin:.25rem 0}
  .hint .lab{color:var(--s1)} .hint .lab-k{color:var(--s2)}
  .pl{margin:.5rem 0;border:1px solid var(--line);border-radius:8px;overflow:hidden}
  .pl-h{display:flex;align-items:center;gap:.5rem;padding:.35rem .6rem;background:var(--surface2);font-size:.8rem}
  .tag{font-family:var(--mono);font-size:.62rem;padding:.08rem .4rem;border-radius:3px;font-weight:700}
  .tag.exploit{background:#3a1416;color:var(--exploit)} .tag.detect{background:#0f2b28;color:var(--detect)}
  .pl-name{color:var(--ink)} .copy{margin-left:auto;background:var(--surface);border:1px solid var(--line);
    color:var(--soft);padding:.15rem .5rem;border-radius:5px;font-size:.72rem}
  pre{margin:0;padding:.55rem .6rem;background:#0a0e13;color:#d7e0e8;font-family:var(--mono);
    font-size:.76rem;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
  .labs{margin-top:.5rem;font-size:.8rem}
  .labs a{display:block;color:var(--soft);text-decoration:none;padding:.1rem 0}
  .labs a:before{content:"↗ ";color:var(--s1)}
  .held{font-size:.72rem;color:var(--faint);font-style:italic}
</style></head>
<body>
<div class="top"><div class="top-row">
  <span class="brand"><span class="dot"></span>wapt · orchestrator</span>
  <span class="pill" id="p-mode">mode <b>—</b></span>
  <span class="pill" id="p-target">target <b>—</b></span>
  <span class="pill" id="p-scope">scope <b>—</b></span>
  <span class="spacer"></span>
  <label class="auto"><input type="checkbox" id="teachme"> 🎓 Teach me</label>
  <label class="auto"><input type="checkbox" id="autopilot"> Autopilot</label>
  <span class="live" id="live">● connecting…</span>
</div></div>

<div id="setup" class="setup-wrap" style="display:none">
  <div class="setup-card">
    <h2>One quick thing 👋</h2>
    <p>Paste your <b>Burp Collaborator</b> address so the tool can catch stolen data.
       In Burp: top menu → <b>Collaborator</b> → <b>Copy to clipboard</b>, then paste here.</p>
    <input id="su-collab" placeholder="e.g. abcd1234.oastify.com" autocomplete="off">
    <details id="su-adv"><summary>Target &amp; exploit server (fill in automatically when you browse — set by hand only if you want to).</summary>
      <input id="su-lab" placeholder="target host(s) — e.g. 0a16….web-security-academy.net  (two boxes? separate with a comma)">
      <input id="su-exp" placeholder="exploit server (optional) — e.g. exploit-0a….exploit-server.net">
    </details>
    <button id="su-save">Save &amp; start</button>
    <p class="setup-skip">The tool only touches hosts in your scope. In lab mode every *.web-security-academy.net lab is in scope automatically, so you rarely need to set this.</p>
  </div>
</div>

<main>
  <div id="learnbar" class="learnbar" style="display:none"></div>
  <div id="donow" class="donow" style="display:none"></div>
  <details class="guide" id="guide">
    <summary>🧭 New here? Start guide (click to expand)</summary>
    <div class="guide-body">
      <p><b>What this is:</b> a to-do board for hacking one target, in 3 stages —
        <b>Stage 1</b> get in as any user, <b>Stage 2</b> become admin,
        <b>Stage 3</b> read the secret file. You browse the target in Burp; findings appear here.</p>
      <ol>
        <li><b>Browse the target in Burp.</b> Click around the site. Cards appear below as the tool spots likely bugs.</li>
        <li><b>Open a card</b> (click its title). It explains the bug in plain words and gives you ready payloads.</li>
        <li><b>Click ⚡ Confirm</b> — the tool safely tests whether the bug is real and tells you yes/no.</li>
        <li><b>Copy a payload</b> (the <span class="tag exploit">exploit</span> ones) and paste it into Burp <b>Repeater</b>, or into the page, as the card's "Next step" says.</li>
        <li>When Stage 1 is done, click <b>Proceed →</b> for the next stage.</li>
      </ol>
      <p class="gloss"><b>Mini-glossary:</b>
        <b>candidate</b> = a possible bug · <b>payload</b> = the attack string you send ·
        <b>Repeater</b> = Burp's tab for editing &amp; resending one request ·
        <b>exfil</b> = steal data out · <b>Collaborator</b> = Burp's server that catches
        pings from blind bugs · <b>confirm</b> = safely prove it's real.</p>
    </div>
  </details>
  <div class="stages" id="stages"></div>
  <div class="killchain" id="killchain" style="display:none"></div>
  <div class="killchain" id="squad" style="display:none"></div>
  <div class="killchain" id="activity" style="display:none"></div>
  <div class="bar">
    <button class="proceed" id="proceed" disabled>Proceed →</button>
    <button class="ghost" id="crawl">🕷 Crawl target</button>
    <button class="ghost" id="settings">⚙ Target / setup</button>
    <button class="ghost" id="reset">Reset</button>
    <a class="ghost btnlink" id="dl" href="/api/report" download>⬇ Download findings</a>
    <a class="ghost btnlink" id="logbtn" href="/api/log" target="_blank">🧾 Probe log</a>
    <span class="count" id="count">0 transactions · 0 endpoints</span>
    <span class="count" id="probes">· 0 probes sent</span>
  </div>
  <div id="board"></div>
</main>
<script>
const $ = s => document.querySelector(s);
const open = new Set();            // remember which cards are expanded across refreshes
let busy = false;
let lastS = null;                  // last snapshot, for prefilling the setup card
let setupPinned = false;           // true while the user has ⚙ open on purpose
let teachOn = false;
try { teachOn = localStorage.getItem('wapt_teach') === '1'; } catch(e){}
const answered = {};               // cid -> true once quiz answered

const CLASS_LABEL = {"reflected-stored-xss":"Reflected/Stored XSS","dom-xss":"DOM XSS",
  "sql-injection":"SQL injection","idor-mass-assign":"IDOR / mass assign","csrf-takeover":"CSRF",
  "ssrf":"SSRF","path-traversal":"Path traversal","os-command-injection":"OS command injection",
  "xxe":"XXE","ssti":"SSTI","jwt-forge":"JWT forge","cors-exfil":"CORS","host-header":"Host header",
  "cache-poisoning":"Cache poisoning","content-discovery":"Content discovery"};

// plain-English: what each bug is, and the very next thing to do about it
const PLAIN = {
  "dom-xss":{w:"Your input runs as JavaScript in the page.",n:"Put the detect payload's URL in the browser; expect an alert. Then use the exploit one to steal a cookie."},
  "web-message-xss":{w:"The page trusts cross-window messages without checking who sent them.",n:"Host the exploit-server payload, deliver to victim."},
  "reflected-stored-xss":{w:"Your input is echoed into the page and runs as code.",n:"Paste the exploit payload into the field/URL; deliver via exploit server to steal the victim's cookie."},
  "sql-injection":{w:"Your input reaches the database query — you can read data you shouldn't.",n:"Click ⚡ Confirm. If confirmed it auto-builds a dump payload — paste it into Burp Repeater to read admin's password."},
  "idor-mass-assign":{w:"You can tamper an ID or add a field (like a role) to act as/affect another user.",n:"Open the request in Repeater; change the id/role field and resend."},
  "csrf-takeover":{w:"An action can be forced on a logged-in victim from your page.",n:"Put the exploit HTML on your exploit server, deliver to the admin."},
  "jwt-forge":{w:"The login token may be forgeable (weak/again unverified signature).",n:"Decode it in the JWT Editor extension; try the alg:none / weak-key payloads."},
  "cors-exfil":{w:"The site hands your page its data cross-origin, with credentials.",n:"Host the exploit-server fetch, deliver to victim, read their data from your log."},
  "ssrf":{w:"The server fetches a URL you control — reach internal stuff or files.",n:"Point the param at Collaborator to confirm, then at localhost / file:// to read the secret."},
  "path-traversal":{w:"A file parameter lets you walk the filesystem.",n:"Put ../../../ paths in the param to read /home/carlos/secret."},
  "ssti":{w:"Your input is rendered by a template engine — often full code execution.",n:"Fuzz the field; {{7*7}} -> 49 confirms Jinja2, then fire the RCE payload."},
  "os-command-injection":{w:"Your input reaches a shell command.",n:"Click ⚡ Confirm (OOB ping). If Collaborator hits, use the exfil payload."},
  "xxe":{w:"An XML parser will fetch external entities — read files / SSRF.",n:"Send the in-band XXE body in Repeater; if nothing reflects, use the OOB DTD."},
  "file-upload-rce":{w:"An upload may let you run server code.",n:"Upload the web shell (try the bypasses), then browse to it."},
  "deserialization":{w:"A serialized blob in a cookie can be tampered into code execution.",n:"Decode the cookie, build the gadget with ysoserial/phpggc, re-wrap."},
  "cache-poisoning":{w:"An unkeyed input gets cached and served to everyone.",n:"Poison a cached script via the header, drop the cache-buster to land it."},
  "host-header":{w:"The Host header is trusted into links (e.g. password reset).",n:"Send the reset with X-Forwarded-Host = your server; catch the token."},
  "request-smuggling":{w:"Front/back-end disagree on request boundaries.",n:"Use the HTTP Request Smuggler extension; keep the 200 response."},
  "user-enum-brute":{w:"Login reveals valid usernames / allows brute force.",n:"Enumerate the user, then Intruder the password."},
  "oauth-takeover":{w:"The social-login flow can be abused to take an account.",n:"Walk the flow in Burp; swap the email on token-submit, or steal the code."},
  "cswsh":{w:"A WebSocket authenticates on cookies only — hijackable cross-site.",n:"Open the socket from the exploit server, relay messages to Collaborator."},
  "content-discovery":{w:"Hidden files/endpoints are exposed (.git, backups, errors).",n:"Fetch the path; read leaked source/creds."},
  "api-graphql":{w:"An API/GraphQL surface exposes extra fields or verbs.",n:"Run GraphQL introspection or try other HTTP methods."},
  "server-side-proto-pollution":{w:"__proto__ in JSON changes server behaviour.",n:"Send isAdmin:true via __proto__, then escalate to RCE via spawn options."},
  "client-side-proto-pollution":{w:"__proto__ in URL/JSON pollutes a gadget into XSS.",n:"Pollute a sink property (e.g. a script src) to reach DOM XSS."},
};

function stageEls(stage){
  const names = {1:["① Get in","become any user"],2:["② Become admin","user → admin"],3:["③ Read the secret","admin → the file"]};
  return [1,2,3].map(n=>{
    const [t,sub]=names[n];
    const done = n<stage;
    return `<div class="stage s${n} ${n===stage?'active':''}">
      <div class="n">STAGE ${n} ${done?'<span class="done">✓ done</span>':''}</div>
      <div class="t">${t}</div><div class="n">${sub}</div></div>`;
  }).join("");
}

function renderDoNow(a){
  const box=$('#donow');
  if(!a){ box.style.display='none'; return; }
  box.style.display='block';
  const steps = (a.steps&&a.steps.length)
    ? `<ol class="dn-steps">${a.steps.map(s=>`<li>${esc(s)}</li>`).join('')}</ol>` : '';
  const pay = a.payload
    ? `<div class="dn-paylabel">${esc(a.payload_name||'payload to copy')}:</div>
       <pre id="donow-pl">${esc(a.payload)}</pre><button class="dn-copy" onclick="cp('donow-pl',this)">📋 copy this</button>`
    : '';
  const terms = (a.terms && Object.keys(a.terms).length)
    ? `<details class="dn-terms"><summary>new words on this card — tap to explain</summary>
       <dl>${Object.keys(a.terms).map(k=>`<dt>${esc(k)}</dt><dd>${esc(a.terms[k])}</dd>`).join('')}</dl></details>`
    : '';
  const stage = a.stage_hint ? `<div class="dn-stage">${esc(a.stage_hint)}</div>` : '';
  box.innerHTML = `<div class="dn-k">⭐ do this now</div>
    <h2>${esc(a.headline)}</h2>
    ${stage}
    <div class="dn-detail">${esc(a.detail||'')}</div>
    ${pay}${steps}${terms}`;
}

function plBlock(c, list, idprefix){
  return list.map((p,j)=>{
    const held = (p.kind==='exploit' && !c.show_exploit);
    const id = `${idprefix}-${c.cid}-${j}`;
    const pre = held ? `<pre class="held">— held (engagement mode). Run with --mode lab to reveal. —</pre>`
                     : `<pre id="${id}">${esc(p.body)}</pre>`;
    const copy = held ? '' : `<button class="copy" onclick="cp('${id}',this)">copy</button>`;
    return `<div class="pl"><div class="pl-h">
        <span class="tag ${p.kind}">${p.kind}</span>
        <span class="pl-name">${esc(p.name)}</span>${copy}</div>${pre}</div>`;
  }).join("");
}
function card(c,i){
  const cls = c.confirmed ? 'confirmed' : c.confidence;
  const tailoredHtml = (c.tailored&&c.tailored.length) ? plBlock(c,c.tailored,'tl') : '';
  const payloadHtml = plBlock(c,c.payloads,'pl');
  const labs = c.labs.map(l=>`<a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener">${esc(l)}</a>`).join("");
  const isOpen = open.has(c.cid);
  const badge = c.confirmed ? `<span class="conf confirmed">confirmed</span>` : `<span class="conf ${cls}">${cls}</span>`;
  return `<div class="card c-${cls} ${isOpen?'open':''}" data-cid="${c.cid}">
    <h3 onclick="tog('${c.cid}')">
      <span class="rank">${String(i+1).padStart(2,'0')}</span>
      ${esc(c.title)}
      ${badge}
      <span class="score">score ${c.score}</span>
    </h3>
    <div class="body">
      ${PLAIN[c.vuln_class]?`<div class="plain"><div><b>What this is:</b> ${esc(PLAIN[c.vuln_class].w)}</div><div><b>Next step:</b> ${esc(PLAIN[c.vuln_class].n)}</div></div>`:''}
      ${teachBlock(c)}
      <div class="kv"><span class="k">where</span><span class="where">${esc(c.location)}</span></div>
      ${c.param?`<div class="kv"><span class="k">param</span><span class="where">${esc(c.param)}</span></div>`:''}
      ${c.evidence?`<div class="kv"><span class="k">why</span>${esc(c.evidence)}</div>`:''}
      <div class="confirm-row">
        <button class="confirmbtn" onclick="confirmCand('${c.cid}',this)">⚡ Confirm (safe probe)</button>
        <span class="confirm-note" id="note-${c.cid}">${c.confirm_note?esc(c.confirm_note):''}</span>
      </div>
      <details class="opts">
        <summary>Show all payload options (advanced)</summary>
        ${c.detect?`<div class="hint"><span class="lab-k">detect</span> ${esc(c.detect)}</div>`:''}
        ${c.play?`<div class="hint"><span class="lab">play</span> ${esc(c.play)}</div>`:''}
        ${tailoredHtml?`<div class="hint" style="margin-top:.5rem"><b style="color:var(--s1)">tailored</b> — built from the real endpoint + param:</div>${tailoredHtml}`:''}
        <div class="hint" style="margin-top:.5rem">canonical reference:</div>
        ${payloadHtml}
      </details>
      ${labs?`<div class="labs"><div class="hint">stuck? these PortSwigger labs are the guide:</div>${labs}</div>`:''}
    </div></div>`;
}
function teachBlock(c){
  if(!teachOn || !c.teach) return '';
  const t=c.teach;
  let quiz='';
  if(t.quiz){
    const opts=t.quiz.options.map((o,i)=>`<button onclick="answerQuiz('${c.cid}',${i},${t.quiz.answer},this)">${esc(o)}</button>`).join('');
    quiz=`<div class="quiz"><div class="q">🧠 Quick check: ${esc(t.quiz.q)}</div>${opts}
      <div class="explain" id="exp-${c.cid}" style="display:none">${esc(t.quiz.explain)}</div></div>`;
  }
  return `<div class="teach">
    <div class="t-k">the pattern — learn to spot this</div>
    <div class="t-row"><b>You saw:</b> ${esc(t.ioc)}</div>
    <div class="t-row"><b>Why it's this bug:</b> ${esc(t.why)}</div>
    <div class="t-row"><b>How to confirm:</b> ${esc(t.tell)}</div>
    ${quiz}</div>`;
}
function answerQuiz(cid, pick, correct, btn){
  const wrap=btn.parentElement;
  [...wrap.querySelectorAll('button')].forEach((b,i)=>{ b.disabled=true;
    if(i===correct) b.classList.add('right'); else if(i===pick) b.classList.add('wrong'); });
  const e=document.getElementById('exp-'+cid); if(e) e.style.display='block';
  answered[cid]=true;
}
function renderLearn(s){
  const bar=$('#learnbar');
  if(!teachOn || !s.learning){ bar.style.display='none'; return; }
  const L=s.learning, conf=new Set(L.confirmed), seen=new Set(L.seen);
  bar.style.display='block';
  const chips=Object.keys(CLASS_LABEL).map(cls=>{
    const cl = conf.has(cls)?'conf':(seen.has(cls)?'seen':'');
    const mark = conf.has(cls)?'✓ ':(seen.has(cls)?'• ':'');
    return `<span class="chip2 ${cl}">${mark}${CLASS_LABEL[cls]}</span>`;
  }).join('');
  bar.innerHTML=`<div class="lb-h">🎓 Your learning — patterns seen ${L.seen.length} · confirmed ${L.confirmed.length} of ${L.total}</div>
    <div class="chips">${chips}</div>`;
}

async function confirmCand(cid, btn){
  btn.textContent='probing…'; btn.disabled=true;
  try{
    const r = await fetch('/api/confirm/'+cid,{method:'POST'});
    const d = await r.json();
    const note = document.getElementById('note-'+cid);
    if(d.ok){ note.textContent = d.note; note.className='confirm-note '+(d.confirmed?'ok':'no'); }
    else { note.textContent = d.err||'probe failed'; note.className='confirm-note no'; }
  }catch(e){ }
  btn.textContent='⚡ Confirm (safe probe)'; btn.disabled=false;
  tick();
}

function esc(s){return (s==null?'':''+s).replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));}
function tog(cid){ open.has(cid)?open.delete(cid):open.add(cid);
  const el=document.querySelector(`.card[data-cid="${cid}"]`); if(el) el.classList.toggle('open'); }
function cp(id,btn){ const t=$('#'+id).innerText; navigator.clipboard.writeText(t).then(()=>{btn.textContent='copied';setTimeout(()=>btn.textContent='copy',1200)});}

async function renderKillchain(){
  try{
    const d = await (await fetch('/api/agents')).json();
    const box = $('#killchain');
    if(!d || !d.stages){ box.style.display='none'; return; }
    const label = {1:'Foothold → get a session',2:'Privesc → reach /admin',3:'Objective → read the secret'};
    const rows = d.stages.map(st=>{
      const on = st.stage===d.current;
      const col = st.solved ? '#2ea043' : (st.lead_class? '#d29922' : '#54636e');
      const lead = st.lead_title
        ? `<b style="color:${col}">${esc(st.lead_title)}</b> <span style="color:#8b98a5">(${esc(st.confidence)})</span>`
        : `<span style="color:#8b98a5">no lead yet — keep browsing</span>`;
      const plan = st.lead_class
        ? `<div style="color:#adbac7;margin:3px 0 0">${esc(st.next)}</div>`
          + (st.payload?`<pre style="margin:4px 0 0;white-space:pre-wrap;color:#7ee787;font-size:11px;max-height:46px;overflow:auto">${esc((st.payload||'').split('\\n')[0].slice(0,140))}</pre>`:'')
          + (st.alternatives&&st.alternatives.length?`<div style="color:#687684;font-size:11px;margin-top:3px">also seen: ${esc(st.alternatives.join(', '))}</div>`:'')
        : `<div style="color:#687684;margin-top:3px">${esc(st.goal)}</div>`;
      return `<div style="padding:9px 11px;border-left:3px solid ${col};background:${on?'#1b2430':'#141a22'};border-radius:6px;margin-bottom:6px">
        <div style="font-weight:600;color:#e6edf3">STAGE ${st.stage} — ${esc(label[st.stage]||st.name)} ${st.solved?'<span style="color:#2ea043">✓ lead ready</span>':''}</div>
        <div style="margin-top:2px">${lead}</div>${plan}</div>`;
    }).join('');
    box.innerHTML = `<div style="font-weight:700;color:#e6edf3;margin:2px 0 7px">🤖 Agent kill-chain — ${d.solved}/3 stages have an actionable lead</div>${rows}`;
    box.style.display='block';
  }catch(e){ /* agents endpoint optional */ }
}

async function renderSquad(){
  try{
    const d = await (await fetch('/api/squad')).json();
    const box = $('#squad');
    if(!d || !d.stages){ box.style.display='none'; return; }
    const rows = d.stages.map(st=>{
      const on = (st.stage===('FOOTHOLD PRIVESC EXFIL'.split(' ')[d.current-1]));
      const chips = st.agents.map(a=>{
        const col = a.confirmed? '#2ea043' : (a.found? '#d29922' : '#2b333c');
        const fg  = a.found? '#0d1117' : '#6b7681';
        const tip = a.found? `${a.where}${a.param?' · '+a.param:''}` : (a.targets||[]).join(', ');
        const mark= a.confirmed? '✓ ' : '';
        return `<span title="${esc(tip)}" style="display:inline-block;margin:2px 3px 0 0;padding:2px 7px;border-radius:10px;font-size:11px;background:${col};color:${fg};font-weight:${a.found?'700':'400'}">${mark}${esc(a.agent)}</span>`;
      }).join('');
      const lead = st.lead? `<b style="color:#d29922">${esc(st.lead)}</b> has the lead` : '<span style="color:#687684">no agent has a lead yet</span>';
      const hits = st.agents.filter(a=>a.found);
      const rank = hits.length? `<div style="margin-top:6px;font-size:12px;color:#adbac7"><b style="color:#e6edf3">Ranked vectors:</b> ${hits.map((a,i)=>`#${i+1} ${esc(a.agent)} <span style="color:#687684">(${esc(a.confidence)}${a.confirmed?' ✓':''})</span>`).join(' · ')}</div>`:'';
      const leadA = hits[0];
      const repro = (leadA && leadA.repro && leadA.repro.length)
        ? `<details style="margin-top:6px"><summary style="cursor:pointer;color:#58a6ff;font-size:12px">▸ Recreate it yourself (${esc(leadA.agent)})</summary>`
          + `<ol style="margin:6px 0 0 2px;padding-left:18px;color:#adbac7;font-size:12px;line-height:1.5">`
          + leadA.repro.map(s=>`<li style="margin-bottom:4px">${esc(s).replace(/\\n\\s*/g,'<br><code style=\"color:#7ee787\">').replace(/$/,'')}</li>`).join('')
          + `</ol></details>` : '';
      return `<div style="padding:8px 10px;border-left:3px solid ${st.solved?'#2ea043':(st.lead?'#d29922':'#54636e')};background:${on?'#1b2430':'#141a22'};border-radius:6px;margin-bottom:6px">
        <div style="font-weight:600;color:#e6edf3">STAGE ${st.stage} · ${st.agents.length} agents up — ${lead}</div>
        <div style="margin-top:5px;line-height:1.9">${chips}</div>${rank}${repro}</div>`;
    }).join('');
    box.innerHTML = `<div style="font-weight:700;color:#e6edf3;margin:2px 0 7px">🛰 Specialist squad — only each stage's own vuln-class agents run</div>${rows}`;
    box.style.display='block';
  }catch(e){ /* squad endpoint optional */ }
}

async function renderActivity(){
  try{
    const d = await (await fetch('/api/activity')).json();
    const box = $('#activity');
    if(!d || !d.items || !d.items.length){ box.style.display='none'; return; }
    const rows = d.items.map(it=>{
      const ok = it.status && it.status<400;
      const sc = it.status? (it.status>=500?'#f85149':(it.status>=400?'#d29922':'#2ea043')) : '#687684';
      return `<div style="display:flex;gap:8px;font-size:11px;font-family:ui-monospace,monospace;padding:2px 0;border-bottom:1px solid #1b222b">
        <span style="color:#687684">${esc(it.time)}</span>
        <span style="color:${sc};min-width:28px">${it.status||'—'}</span>
        <span style="color:#adbac7;flex:1">${esc(it.note||it.url)}</span></div>`;
    }).join('');
    box.innerHTML = `<div style="font-weight:700;color:#e6edf3;margin:2px 0 7px">📡 Agents testing — live (${d.total} probes fired)</div>${rows}`;
    box.style.display='block';
  }catch(e){ /* activity endpoint optional */ }
}

async function tick(){
  if(busy) return;
  try{
    const r = await fetch('/api/state'); const s = await r.json();
    $('#p-mode').innerHTML = `mode <b>${s.mode}</b> · ${s.profile}`;
    $('#p-target').innerHTML = `target <b>${esc(s.lab||'unset')}</b>`;
    $('#p-scope').innerHTML = `scope <b>${esc(s.scope||'—')}</b>`;
    $('#stages').innerHTML = stageEls(s.stage);
    $('#count').textContent = `${s.txns} transactions · ${s.endpoints} endpoints`;
    $('#probes').textContent = `· ${s.probes||0} probes` + (s.crawling?` · 🕷 crawling… ${s.crawl_pages} pages`:'');
    const cb=$('#crawl'); cb.disabled=!!s.crawling; cb.textContent=s.crawling?'🕷 crawling…':'🕷 Crawl target';
    lastS = s;
    // setup wizard: show until Collaborator is set, or when summoned via ⚙
    $('#setup').style.display = (s.needs_setup || setupPinned) ? 'flex' : 'none';
    // autopilot checkbox reflects server state
    const ap=$('#autopilot'); if(document.activeElement!==ap) ap.checked = !!s.autopilot;
    // the one big next action + learning progress
    renderDoNow(s.next_action);
    renderLearn(s);
    renderKillchain();
    renderSquad();
    renderActivity();
    const ago = s.last_ingest_ago;
    $('#live').innerHTML = ago==null ? '● <span style="color:#67788a">waiting for traffic…</span>'
      : (ago<5 ? '<span class="on">● live</span>' : `● last ${ago}s ago`);
    const pb = $('#proceed');
    pb.disabled = !s.can_advance;
    pb.textContent = s.can_advance ? `Proceed to Stage ${s.next_stage} →` : 'Stage 3 — final';
    const board = $('#board');
    if(!s.candidates.length){
      board.innerHTML = `<div class="empty">No candidates yet for Stage ${s.stage}.<br>Browse the target in Burp — signals will stream in here.</div>`;
    } else {
      board.innerHTML = s.candidates.map(card).join("");
    }
  }catch(e){ $('#live').innerHTML='● <span style="color:#f0616b">engine offline</span>'; }
}

$('#proceed').onclick = async ()=>{ busy=true; await fetch('/api/proceed',{method:'POST'}); busy=false; tick(); };
$('#reset').onclick = async ()=>{ if(!confirm('Clear all captured traffic and go back to Stage 1?'))return;
  busy=true; open.clear(); await fetch('/api/reset',{method:'POST'}); busy=false; tick(); };
$('#autopilot').onchange = async (e)=>{ await fetch('/api/autopilot',{method:'POST',
  headers:{'Content-Type':'application/json'},body:JSON.stringify({on:e.target.checked})}); tick(); };
$('#crawl').onclick = async ()=>{ await fetch('/api/crawl',{method:'POST'}); tick(); };
$('#teachme').checked = teachOn;
$('#teachme').onchange = (e)=>{ teachOn=e.target.checked;
  try{ localStorage.setItem('wapt_teach', teachOn?'1':'0'); }catch(_){}
  open.clear(); tick(); };
$('#settings').onclick = ()=>{
  setupPinned = true;
  // prefill with whatever the engine currently has
  if(lastS){
    if(lastS.collab) $('#su-collab').value = lastS.collab;
    if(lastS.lab)    $('#su-lab').value    = lastS.scope && lastS.scope!=='(none)' ? lastS.scope : lastS.lab;
    if(lastS.exploit)$('#su-exp').value    = lastS.exploit;
  }
  $('#su-adv').open = true;
  $('#setup').style.display = 'flex';
  $('#su-lab').focus();
};
$('#su-save').onclick = async ()=>{
  const collab=$('#su-collab').value.trim();
  // Collaborator is only required the first time (OOB bugs need it); if it's
  // already set, allow saving just a target change.
  if(!collab && !(lastS && lastS.collab)){ $('#su-collab').focus(); return; }
  await fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({collab, lab:$('#su-lab').value.trim(), exploit:$('#su-exp').value.trim()})});
  setupPinned = false;
  tick();
};

// Esc closes the setup card when it was opened on purpose
document.addEventListener('keydown', (e)=>{ if(e.key==='Escape' && setupPinned){ setupPinned=false; $('#setup').style.display='none'; }});

tick(); setInterval(tick, 2000);
</script>
</body></html>
"""
