"""Teach Me — the pattern lesson behind each finding.

For every vuln class:
  ioc  : what you SAW (the pattern to recognise in traffic)
  why  : why that means this bug (the mechanism)
  tell : how you CONFIRM it
  quiz : a multiple-choice self-check {q, options, answer(index), explain}

This is the educational core — it turns each finding into a one-minute lesson
so a learner builds the recognition reflex, not just a copy-paste habit.
"""
from __future__ import annotations


def _L(ioc, why, tell, q, options, answer, explain):
    return {"ioc": ioc, "why": why, "tell": tell,
            "quiz": {"q": q, "options": options, "answer": answer, "explain": explain}}


LESSONS = {
    "sql-injection": _L(
        "A single quote ' changed the page — a DB error, or more/fewer results. Spots: search, category/sort filters, the TrackingId cookie.",
        "Your input is glued straight into an SQL query, so a quote ends the string early and the rest is read as SQL.",
        "' AND '1'='1 looks normal but ' AND '1'='2 differs = boolean oracle. A quote that errors = error-based. Then UNION SELECT to read other tables.",
        "A single quote makes the results page show MORE items than normal. What does that mean?",
        ["Nothing — random", "It's SQL-injectable; the quote broke the WHERE filter", "It's XSS"],
        1, "The quote broke the WHERE clause so the filter stopped applying and everything matched — a classic injectable tell."),

    "reflected-stored-xss": _L(
        "Something you typed comes back in the page (reflected now, or stored and shown later in comments/profiles).",
        "The app writes your input into HTML without encoding it, so your tags/script become part of the page.",
        "Send a canary with specials (\"<svg>). If they come back RAW (not &lt;svg&gt;) it's injectable; the CONTEXT picks the payload.",
        "Your canary comes back as &lt;svg&gt; in the response. Exploitable?",
        ["Yes, always", "No — it's HTML-encoded, shown as text", "Only on Fridays"],
        1, "Encoded means the browser renders it as text, not a tag. You need a spot where it comes back raw."),

    "dom-xss": _L(
        "Page JavaScript reads something you control (location.search/hash, postMessage) and feeds it to a sink (innerHTML, eval, document.write).",
        "The bug is in the page's own JS — your value reaches code execution client-side, no server reflection needed.",
        "Find the source→sink in the JS (or DOM Invader). For an eval/JSON sink a string break-out like \"-alert(1)}// runs — not an <img>.",
        "Your input lands inside a JSON response the page passes to eval(). Which payload?",
        ["<img src=1 onerror=alert(1)>", "\"-alert(1)}//  (string break-out)", "' OR 1=1--"],
        1, "It's JavaScript, not HTML — you break out of the string and the rest runs as code. <img> only works in HTML context."),

    "web-message-xss": _L(
        "An addEventListener('message', …) handler with NO check of e.origin.",
        "Any site can postMessage to this page; without an origin check the handler trusts attacker data, often into a sink.",
        "Frame the page from your exploit server and postMessage a payload into the sink.",
        "The message handler verifies e.origin against a whitelist. Still exploitable via web messages?",
        ["Yes", "Usually not — the origin check is the defence", "Only with SQLi"],
        1, "The origin check stops cross-site pages from feeding it data. Look for handlers that skip it."),

    "path-traversal": _L(
        "A parameter names a file (filename=, file=, path=) and there's NO size/width param.",
        "../ sequences walk up out of the intended folder to any file the app can read.",
        "../../../../etc/passwd returns root:x:0:0 = traversal; then swap in /home/carlos/secret. Filters? double-encode (..%252f) or null-byte.",
        "Why does an image loader WITHOUT a size param hint at traversal, not command injection?",
        ["It doesn't", "No size param = it just reads the file by name (traversal), not resizing via a shell", "Because PHP"],
        1, "A resize (shell) step is where cmdi hides; a plain read-by-name is where traversal hides."),

    "os-command-injection": _L(
        "Input reaches a shell: image size params (ImgSize), feedback/contact fields, or an XML email field.",
        "The app builds a shell command with your input, so metacharacters (` ; | $()) run extra commands.",
        "Output rarely shows — go out-of-band: a backtick nslookup to your Collaborator. A DNS hit = confirmed.",
        "You injected a command but the response shows nothing. Did it fail?",
        ["Yes, it failed", "Not necessarily — most cmdi is blind; confirm out-of-band", "It's SSRF"],
        1, "Most command injection is blind. Confirm with an out-of-band ping/nslookup to Collaborator, not the page body."),

    "ssrf": _L(
        "A parameter carries a URL the SERVER fetches — stock checkers, 'download/generate report' (PDF), avatar-by-URL.",
        "The server makes the request for you, so you can reach internal services or file:// you can't hit directly.",
        "Point it at Collaborator (a hit confirms), then at http://localhost/… or file:///home/carlos/secret.",
        "Why is SSRF powerful even though you can already browse the site?",
        ["It isn't", "The SERVER fetches it from inside the network — reaching internal-only hosts & local files", "It bypasses CSS"],
        1, "The request originates server-side, so you reach internal-only hosts and local files you never could directly."),

    "xxe": _L(
        "Any XML body/upload (stock check, SOAP, import), or a JSON endpoint you can switch to Content-Type: application/xml.",
        "The XML parser resolves external entities, so a declared entity pulls in a local file or makes a server request.",
        "Declare an entity for file:///etc/passwd where a value is reflected. Nothing reflects? exfil out-of-band with an external DTD.",
        "The XML response doesn't echo your value. Is XXE dead here?",
        ["Yes", "No — use blind/out-of-band XXE with a malicious external DTD", "Switch to JSON"],
        1, "Blind XXE: a DTD on your server makes the parser send the file to your Collaborator."),

    "ssti": _L(
        "Input is rendered by a template engine — reset/email template editors, or an 'out of stock' view reflecting your text.",
        "Your input is treated as template CODE not data, so template syntax executes — often full RCE.",
        "Fuzz ${{<%[%'\"}} → a 500 = SSTI. {{7*7}} → 49 and {{7*'7'}} → 7777777 = Jinja2.",
        "{{7*7}} returns 49 on the page. What does that tell you?",
        ["Nothing", "The server evaluated it — SSTI, and 49 points to a Python engine (Jinja2)", "It's XSS"],
        1, "The server computed your expression (49, not the literal 77) — that's SSTI, pointing at Jinja2."),

    "file-upload-rce": _L(
        "An upload (avatar, import) or a 'set image by URL' the server fetches and might execute.",
        "If you upload a server-side script (.php/.phtml) to a place that executes it, browsing to it runs your code.",
        "Upload a tiny PHP shell; beat filters with content-type spoof, alt extensions, .htaccess, filename traversal.",
        "You uploaded shell.php but it downloads instead of running. What's wrong?",
        ["The shell is broken", "It must land where the server EXECUTES PHP — wrong folder/handler = just a file", "Use .txt"],
        1, "Execution depends on where it lands and the handler. Find a path the server actually runs as code."),

    "deserialization": _L(
        "A cookie/field is a serialized blob: PHP O:/a:, Java rO0AB (base64) / ac ed bytes, gzip H4sI.",
        "The app rebuilds an object from your bytes; tampering fields or chaining gadget classes flips privilege or runs code.",
        "Decode it, flip a field (admin flag / type-juggle) and watch behaviour change, or use a gadget chain (ysoserial/phpggc).",
        "A cookie decodes to O:4:\"User\":2:{s:5:\"admin\";b:0;}. First thing to try?",
        ["Full RCE gadget chain", "Flip the serialized field (b:0→b:1) for privilege", "Delete the cookie"],
        1, "Start simple: tamper the field for privilege escalation before reaching for a full gadget chain."),

    "idor-mass-assign": _L(
        "An ID in the URL/body picks whose data you see (?id=carlos), or a response returns extra fields like roleid.",
        "The app trusts a client-supplied id/field with no ownership/role check — you read or set what you shouldn't.",
        "Change the id to another user; add the leaked field (roleid) to the update request; brute unknown role numbers.",
        "The change-email response JSON includes \"roleid\":2 that you never sent. Why care?",
        ["It's just noise", "You can probably SET it too (mass assignment) — grant yourself a role", "It's a CSRF token"],
        1, "A field the server returns is often one you can also submit — add roleid to escalate."),

    "csrf-takeover": _L(
        "A state-changing POST (change email/password) with a missing, reusable, or not-session-tied CSRF token.",
        "If the action needs no secret only you know, a page you control can make the victim's browser perform it.",
        "Drop the token — still works? Token from another session accepted? Then an auto-submit form on your exploit server does it.",
        "Change-email still succeeds after you delete the csrf parameter. What did you prove?",
        ["Nothing", "The token isn't enforced — it's CSRF-able", "The server is down"],
        1, "Not enforced = CSRF-able. A hidden auto-submitting form will trigger it on the victim."),

    "cors-exfil": _L(
        "A credentialed API reflects your Origin into Access-Control-Allow-Origin AND sets Allow-Credentials: true.",
        "The browser then hands your page the victim's authenticated response cross-origin — you read their data.",
        "Add Origin: https://evil to a sensitive request; if reflected with credentials allowed, fetch it from your exploit server.",
        "ACAO reflects your Origin but Allow-Credentials is absent. Read the victim's private data?",
        ["Yes", "No — without credentials the request isn't authenticated", "Only their public data, which is the goal"],
        1, "No credentials = unauthenticated cross-origin request, so you only get public data."),

    "jwt-forge": _L(
        "A 3-part xxx.yyy.zzz token in a cookie/Authorization header.",
        "If the signature isn't properly verified (alg:none, weak secret, jwk/jku/kid), you can rewrite the claims.",
        "Decode header+payload; try alg:none, crack a weak HMAC secret, or inject your key via jwk/jku/kid.",
        "You change the JWT payload to role=admin and it's accepted unchanged. What was broken?",
        ["Nothing", "The signature wasn't verified — the server trusted the payload", "The cookie expired"],
        1, "The server didn't check the token was signed by it, so your edited claims were trusted."),

    "oauth-takeover": _L(
        "A 'log in with…' button; watch /auth for client_id, redirect_uri, response_type, scope — and whether state is present.",
        "Missing state (CSRF), trusting a client-supplied email, or a loose redirect_uri lets you link/hijack accounts or steal the code.",
        "Swap the email on the token-submit, or hijack redirect_uri to capture the victim's code/token, then replay.",
        "The OAuth flow has no 'state' parameter. Which attack does that open?",
        ["SQLi", "CSRF on the linking step (force-link accounts)", "None"],
        1, "No state = the linking step is CSRF-able; you can force-link your social account to the victim's."),

    "cswsh": _L(
        "A wss:// WebSocket authenticated purely on cookies — no CSRF token, no SameSite protection.",
        "Your page can open the socket in the victim's context and read/relay everything (chat often holds secrets).",
        "From your exploit server, open the socket and relay each message to Collaborator.",
        "The WebSocket handshake carries a per-session CSRF token. Still hijackable cross-site?",
        ["Yes", "No — the token stops a cross-site page opening it", "Only over HTTP"],
        1, "Cookie-ONLY auth is the vulnerable pattern; a CSRF token on the handshake defends it."),

    "cache-poisoning": _L(
        "Cacheable responses (X-Cache: hit, Age) where an UNKEYED input (e.g. X-Forwarded-Host) is reflected into a script/page.",
        "You poison the cached copy once; everyone (incl. admins) is then served your injected content.",
        "Confirm caching (miss→hit), put a canary in the unkeyed header, see it reflected, then drop the cache-buster to land it.",
        "Why must the injected input be UNKEYED for cache poisoning?",
        ["It mustn't", "Unkeyed = not in the cache key, so it's stored & replayed under the normal URL", "Keyed is faster"],
        1, "If it were keyed, your malicious value would get its own cache entry and never reach other users."),

    "host-header": _L(
        "The Host (or X-Forwarded-Host) header is reflected into links — especially a password-reset email link.",
        "If the reset URL is built from a header you control, you point the victim's reset token at your server.",
        "Trigger a reset with X-Forwarded-Host: your-server; the victim's token lands in your access log.",
        "Why does controlling Host on a password-reset endpoint matter so much?",
        ["It doesn't", "The reset link is built from it — the victim's one-time token goes to YOUR domain", "It changes the title"],
        1, "The token-bearing link is generated from the header, so you receive the victim's reset token."),

    "request-smuggling": _L(
        "Front-end and back-end disagree on length — both Transfer-Encoding and Content-Length present; a smuggle probe returns 200 not 400.",
        "The desync lets you prepend a hidden request to the next user's — reaching blocked paths or poisoning their response.",
        "Use HTTP Request Smuggler; keep the request that returns 200. Content-Length must be byte-exact.",
        "In a CL.TE smuggle, which header does the FRONT-end trust?",
        ["Transfer-Encoding", "Content-Length (the back-end uses TE)", "Neither"],
        1, "Front-end=CL, back-end=TE — that disagreement is the whole bug."),

    "user-enum-brute": _L(
        "Login differs for valid vs invalid usernames (wording, status, timing); weak lockout; or a brute-forceable 2FA step.",
        "Any observable difference lets you first find real usernames, then brute the password or 2FA code.",
        "Diff valid vs invalid responses (even a trailing '.' differs). Rotate X-Forwarded-For to dodge IP lockout.",
        "'Invalid username' vs 'Invalid password' are different messages. Why is that a finding?",
        ["It's helpful UX", "It leaks which usernames exist (enumeration)", "It's a typo"],
        1, "Different messages reveal valid usernames — now you know exactly what to brute-force."),

    "content-discovery": _L(
        "Exposed files/paths: /.git, backups (.bak, ~), robots.txt hints, verbose error/stack-trace pages.",
        "Leaked source, configs or version-control history often hand you creds or the next step directly.",
        "Fetch the path; read the leaked content. .git history frequently contains admin credentials.",
        "You find /.git/ is browsable. Why is that often game-over?",
        ["It's just metadata", "You can rebuild the source + history, which routinely holds secrets/creds", "It logs you out"],
        1, "Version control history commonly contains hard-coded credentials and the full source."),

    "api-graphql": _L(
        "An API surface: /api, /v1, Swagger, or a /graphql endpoint; extra HTTP methods accepted.",
        "Docs/introspection reveal hidden fields and mutations; mass-assignment and unused endpoints are common.",
        "Run GraphQL introspection to dump the schema; try other verbs; look for privileged fields you can set.",
        "What does GraphQL introspection give an attacker?",
        ["Nothing useful", "The full schema — every query/mutation/field to abuse", "The admin password"],
        1, "Introspection returns the whole schema, exposing hidden and privileged operations."),

    "client-side-proto-pollution": _L(
        "__proto__ in a URL/JSON is honoured — Object.prototype.x shows up in the console afterwards.",
        "Polluting a shared prototype property the app later reads as config (a script src, isAdmin) reaches DOM XSS/privilege.",
        "Inject __proto__[x]=y, verify Object.prototype.x, then pollute a gadget the app uses as a sink.",
        "Prototype pollution alone rarely 'does' anything. What makes it exploitable?",
        ["Luck", "A gadget — code that later reads the polluted property as a sink/config", "A second server"],
        1, "You need a gadget: app code that reads the polluted property (e.g. a script URL) and turns it into XSS/privilege."),

    "server-side-proto-pollution": _L(
        "Sending __proto__ in a JSON body changes server behaviour (even with nothing reflected).",
        "Node merges your object into internals; polluting spawn options (execArgv/NODE_OPTIONS) can reach RCE.",
        "Send {\"__proto__\":{\"isAdmin\":true}} and watch for a behaviour change; then escalate via a spawn-option gadget.",
        "No reflection, but adding __proto__ to JSON changes a response field. Significant?",
        ["No", "Yes — the server merged your pollution into internals; escalate toward RCE", "It's cached"],
        1, "A behaviour change with no reflection means server-side pollution took effect — a path toward privilege/RCE."),

    "password-reset-logic": _L(
        "The reset flow: is the token tied to the user, removable, or host-controlled? Can change-password skip the current password?",
        "Broken logic lets you reset someone else's password or set yours as administrator's.",
        "Drop the token and set username=administrator; or change-password without the current one.",
        "You delete the reset token, set username=administrator, and it works. The flaw?",
        ["None", "The token wasn't tied to the account — no proof of ownership", "The email bounced"],
        1, "The server reset whoever you named without verifying ownership via the token."),
}

GENERIC = _L(
    "An input or response shape that commonly maps to this bug class.",
    "The app trusts attacker-controlled data somewhere it shouldn't.",
    "Send a safe probe and compare the response to a normal baseline.",
    "What's the general rule for confirming a bug safely?",
    ["Fire the exploit immediately", "Change one thing, compare to a baseline, look for a tell-tale difference", "Guess"],
    1, "Minimal differential probing: one change vs a baseline, and watch for a difference only a real bug causes.")


def lesson(cls: str) -> dict:
    return LESSONS.get(cls, GENERIC)


def count() -> int:
    return len(LESSONS)


# public aliases used across the codebase
teach = lesson
total_patterns = count
