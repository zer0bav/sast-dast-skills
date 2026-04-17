---
name: blackbox-infodisclosure
description: >-
  Actively test a target web application for information disclosure and
  sensitive data exposure vulnerabilities using blackbox techniques. Reads
  pentest/target-map.md, probes for error messages revealing stack traces/paths,
  exposed debug endpoints, sensitive files (.env, backup files, .git), API
  responses leaking internal data, verbose security headers, and source code
  exposure. Writes confirmed findings to pentest/infodisclosure-results.md.
---

# Blackbox Information Disclosure Detection

You are actively testing a web application for information disclosure and sensitive data exposure without source code access. You will probe for error messages, exposed files, debug endpoints, and over-returning APIs that reveal internal implementation details or sensitive data.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## Phase 1: Error-Triggered Information Disclosure

### Test 1: Trigger Verbose Error Pages

```bash
# Invalid input to trigger error messages
curl -sk "<TARGET_URL>/api/users/notanumber"
curl -sk "<TARGET_URL>/api/items/99999999"
curl -sk "<TARGET_URL>/date?d=invaliddate"
curl -sk "<TARGET_URL>/api/data?format=invalid"

# Invalid content type
curl -sk -X POST "<TARGET_URL>/api/data" \
  -H "Content-Type: invalid/type" \
  -d "test"

# Malformed JSON
curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d "{this is not json}"

# Stack overflow via deep recursion (if accepted)
curl -sk -X POST "<TARGET_URL>/api/data" \
  -H "Content-Type: application/json" \
  -d '{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{}}}}}}}}}}}}'
```

**Look for in responses**:
- Stack traces with file paths (`/var/www/html/app.py`, `C:\inetpub\...`)
- Framework versions (`Django 2.1.7`, `Spring 5.3.1`)
- Database connection strings or errors (`SQLSTATE[HY000]`, `ORA-00001`)
- Internal IP addresses
- Developer comments or debug info

### Test 2: HTTP Method Enumeration

```bash
# Send unusual HTTP methods
for METHOD in TRACE TRACK OPTIONS DEBUG PUT DELETE PATCH PROPFIND; do
  echo "Testing $METHOD:"
  curl -sk -X $METHOD "<TARGET_URL>/" -D - | head -10
done

# TRACE reflects request back — reveals cookies, headers
curl -sk -X TRACE "<TARGET_URL>/" -D -
```

**TRACE enabled** = Low severity (XST — Cross-Site Tracing). Can reveal `HttpOnly` cookies to JS via `fetch()`.

---

## Phase 2: Sensitive File Discovery

```bash
TARGET="<TARGET_URL>"

# Environment and config files
for PATH in /.env /.env.local /.env.production /.env.backup \
            /config.php /config.yml /config.json /settings.py \
            /wp-config.php /configuration.php /application.yml \
            /database.yml /secrets.yml /appsettings.json; do
  STATUS=$(curl -sk -o /tmp/resp.txt -w "%{http_code}" "${TARGET}${PATH}")
  if [ "$STATUS" = "200" ]; then
    echo "[200] $PATH — $(wc -c < /tmp/resp.txt) bytes"
    head -5 /tmp/resp.txt
  fi
done

# Backup files
for EXT in .bak .backup .old .orig .1 .tmp ~; do
  for FILE in /index.php /config.php /main.py /app.py /server.js; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${FILE}${EXT}")
    [ "$STATUS" = "200" ] && echo "[200] ${FILE}${EXT}"
  done
done

# Source code exposure
for PATH in /index.php.bak /app.py.bak /main.go /server.js.bak \
            /robots.txt /sitemap.xml /.htaccess /.htpasswd \
            /crossdomain.xml /clientaccesspolicy.xml; do
  STATUS=$(curl -sk -o /tmp/resp.txt -w "%{http_code}" "${TARGET}${PATH}")
  [ "$STATUS" = "200" ] && echo "[200] $PATH — $(head -2 /tmp/resp.txt)"
done
```

### Git Repository Exposure

```bash
# Check if .git directory is exposed
curl -sk -o /dev/null -w "%{http_code}" "<TARGET_URL>/.git/HEAD"
# 200 = exposed git repo

# If exposed, extract the repo
curl -sk "<TARGET_URL>/.git/HEAD"
curl -sk "<TARGET_URL>/.git/config"
curl -sk "<TARGET_URL>/.git/COMMIT_EDITMSG"
curl -sk "<TARGET_URL>/.git/logs/HEAD"
```

**Confirmed git exposure** if `/.git/HEAD` returns `ref: refs/heads/main` or similar.

---

## Phase 3: Debug & Admin Endpoint Exposure

```bash
TARGET="<TARGET_URL>"

# Spring Boot Actuator
for EP in /actuator /actuator/health /actuator/env /actuator/mappings \
           /actuator/beans /actuator/configprops /actuator/heapdump \
           /actuator/threaddump /actuator/logfile; do
  STATUS=$(curl -sk -o /tmp/resp.txt -w "%{http_code}" "${TARGET}${EP}")
  if [ "$STATUS" = "200" ]; then
    echo "[200] $EP — ACTUATOR EXPOSED:"
    head -3 /tmp/resp.txt
  fi
done

# Django debug
curl -sk "${TARGET}/__debug__/"
curl -sk "${TARGET}/_debug_toolbar/"

# PHP info
for PATH in /phpinfo.php /php_info.php /info.php /test.php /check.php; do
  STATUS=$(curl -sk -o /tmp/resp.txt -w "%{http_code}" "${TARGET}${PATH}")
  if [ "$STATUS" = "200" ]; then
    echo "[200] $PATH — PHP Info exposed"
    grep -o "PHP Version [0-9.]*" /tmp/resp.txt | head -1
  fi
done

# General debug endpoints
for PATH in /debug /status /health /metrics /version /server-status \
            /server-info /_status /api/status /api/version /api/health; do
  STATUS=$(curl -sk -o /tmp/resp.txt -w "%{http_code}" "${TARGET}${PATH}")
  if [ "$STATUS" = "200" ]; then
    echo "[200] $PATH:"
    head -5 /tmp/resp.txt
  fi
done

# Swagger/OpenAPI
for PATH in /swagger-ui.html /swagger /api-docs /openapi.json /swagger.json \
            /v2/api-docs /v3/api-docs /api/swagger; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${PATH}")
  [ "$STATUS" = "200" ] && echo "[200] $PATH — API docs exposed"
done
```

---

## Phase 4: API Over-Returning Data

Check if API responses include more data than necessary:

```bash
# Your own profile — does it include sensitive fields?
curl -sk "<TARGET_URL>/api/me" -H "Authorization: Bearer <TOKEN>"
# Look for: password_hash, secret key, internal IDs, admin flags

# User list — does it expose all data?
curl -sk "<TARGET_URL>/api/users" -H "Authorization: Bearer <TOKEN>"
# Look for: emails, phone numbers, addresses, payment info, hashed passwords

# Error responses
curl -sk "<TARGET_URL>/api/users/99999" -H "Authorization: Bearer <TOKEN>"
# Look for: SQL errors, internal paths, object field names
```

---

## Phase 5: Response Header Analysis

```bash
curl -sk -D - -o /dev/null "<TARGET_URL>/"
```

**Check for disclosed info in headers**:
- `Server: Apache/2.4.49` — version disclosure (check for known CVEs)
- `X-Powered-By: PHP/7.4.3` — technology and version disclosure
- `X-AspNet-Version:` — .NET version
- `X-Debug-Token:` — Symfony debug info
- `X-Debug-Token-Link:` — debug profiler URL exposed

---

## Output Format

Write findings to `pentest/infodisclosure-results.md`:

```markdown
# Information Disclosure Assessment Results

## Summary
- Tests performed: [N]
- Critical disclosures: [N]
- High disclosures: [N]
- Medium/Low disclosures: [N]

## Findings

### [CRITICAL] .env file exposed — Database credentials and API keys

- **URL**: `https://target.com/.env`
- **HTTP Status**: 200
- **Contents** (excerpt):
  ```
  DB_HOST=prod-db.internal.company.com
  DB_PASSWORD=SuperSecret123!
  AWS_ACCESS_KEY_ID=AKIA...
  AWS_SECRET_ACCESS_KEY=...
  JWT_SECRET=weakjwtsecret
  ```
- **Impact**: Full database credentials, AWS IAM keys, JWT signing secret — complete account and infrastructure compromise
- **PoC**: `curl -sk https://target.com/.env`
- **Remediation**: Remove `.env` from web root. Configure web server to deny access to dot-files. Use environment variables injected at runtime, not file-based secrets in web-accessible locations.

### [HIGH] Spring Boot Actuator /actuator/env exposed

- **URL**: `https://target.com/actuator/env`
- **HTTP Status**: 200
- **Contents**: Full environment variables including DB credentials, API keys, JVM arguments
- **PoC**: `curl -sk https://target.com/actuator/env | python3 -m json.tool`
- **Remediation**: Secure actuator endpoints behind authentication. In application.properties: `management.endpoints.web.exposure.include=health` and require auth: `management.endpoint.health.roles=ACTUATOR_ROLE`.

### [HIGH] Git repository exposed at /.git/

- **URL**: `https://target.com/.git/HEAD`
- **HTTP Status**: 200
- **Contents**: `ref: refs/heads/main`
- **Impact**: Full source code reconstruction — exposes hardcoded secrets, business logic, authentication bypass opportunities
- **PoC**:
  ```bash
  curl -sk https://target.com/.git/HEAD
  # → ref: refs/heads/main
  curl -sk https://target.com/.git/config
  curl -sk https://target.com/.git/COMMIT_EDITMSG
  ```
- **Remediation**: Block access to `.git` directory in web server config. Nginx: `location /.git { deny all; }`. Apache: `<DirectoryMatch "^/.*/\.git/">Deny from all</DirectoryMatch>`.

### [MEDIUM] Verbose stack trace on invalid input

- **Endpoint**: `GET /api/users/abc`
- **Evidence**: Full Python/Django traceback with file paths, line numbers, and source code snippets
- **Impact**: Reveals framework, internal file paths, application structure
- **Remediation**: Configure `DEBUG=False` in production. Use custom error pages that show no implementation details.

### [LOW] Server version disclosed in header

- **Header**: `Server: Apache/2.4.49`
- **Impact**: Enables targeted CVE search (CVE-2021-41773 path traversal exists for Apache 2.4.49)
- **Remediation**: Set `ServerTokens Prod` and `ServerSignature Off` in Apache config.
```

---

## Important Reminders

- An exposed `.env` file is an immediate Critical finding — read it fully.
- Spring Boot Actuator `/heapdump` can expose in-memory secrets — note it even if credentials aren't visible.
- Exposed `.git` repos can be fully reconstructed with `git-dumper` tool.
- `TRACE` method = Low severity alone, but combined with sensitive cookies it enables XST.
- Clean up: write directly to `pentest/infodisclosure-results.md`.
