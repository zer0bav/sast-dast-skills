---
name: blackbox-recon
description: >-
  Perform blackbox reconnaissance against a target URL/domain to map the
  attack surface without source code access. Crawls pages, extracts
  parameters, discovers API endpoints, identifies authentication mechanisms,
  and writes a structured target map to pentest/target-map.md. This skill
  must run before all other blackbox skills. Use when starting a blackbox
  pentest or when asked to map the attack surface of a target.
---

# Blackbox Reconnaissance & Target Mapping

You are performing the initial reconnaissance phase of a blackbox penetration test. Your goal is to map the target's full attack surface — endpoints, parameters, authentication mechanisms, and technology stack — using only HTTP requests. You have no access to source code.

**Output**: Write all findings to `pentest/target-map.md`.

---

## Phase 1: Passive Information Gathering

Before sending any active requests, collect passive intelligence.

### 1.1 Technology Fingerprinting

Send a GET request to the target root URL and inspect the response:

```
curl -sk -D - "<TARGET_URL>" -o /dev/null
```

Look for:
- **Server header**: Apache, Nginx, IIS, Cloudflare, etc.
- **X-Powered-By**: PHP, ASP.NET, Express, etc.
- **Set-Cookie names**: `PHPSESSID` (PHP), `JSESSIONID` (Java), `ASP.NET_SessionId` (.NET), `session` / `_session` (Rails/Flask)
- **Content-Type and charset**
- **X-Frame-Options, Content-Security-Policy, X-XSS-Protection** (security headers — note absences)
- **Response body**: Look for framework-specific HTML patterns, meta generators (e.g. `<meta name="generator">`), JS bundle names

### 1.2 Common File Discovery

Check for commonly exposed files that reveal technology and configuration:

```bash
# Check each with: curl -sk -o /dev/null -w "%{http_code}" <TARGET_URL>/<path>
robots.txt
sitemap.xml
.well-known/security.txt
crossdomain.xml
clientaccesspolicy.xml
humans.txt
/api
/api/v1
/api/v2
/graphql
/swagger.json
/swagger/v1/swagger.json
/openapi.json
/api-docs
/v1
/v2
/admin
/login
/signin
/register
/signup
/dashboard
/console
/actuator          # Spring Boot
/actuator/health
/actuator/env
/actuator/mappings
/__debug__         # Django debug toolbar
/debug
/health
/status
/metrics
/.env
/phpinfo.php
/info.php
/wp-login.php      # WordPress
/wp-admin          # WordPress
/xmlrpc.php        # WordPress
/rest/api/latest/serverInfo  # Jira
```

For each path returning 200, 301, 302, or 403: record it.

### 1.3 DNS & Certificate Recon (passive)

If you have `curl` and can reach external services:

```bash
# Attempt certificate transparency lookup
curl -sk "https://crt.sh/?q=<DOMAIN>&output=json" | head -c 5000
```

Extract unique subdomains/hostnames from the certificate log.

---

## Phase 2: Active Crawling & Parameter Extraction

### 2.1 Crawl Key Pages

For each discovered page and the root, fetch the HTML and extract:
- All `<a href>` links (internal only — stay on the same domain)
- All `<form>` elements: action URL, method, input names and types
- All `<script src>` references (may reveal JS bundles, CDN, API endpoints)
- All `fetch()`/`axios`/`xhr` calls visible in inline scripts
- All visible API endpoint strings in JS source

Use curl to fetch pages:
```bash
curl -sk -L --max-redirs 5 -A "Mozilla/5.0" "<PAGE_URL>"
```

### 2.2 JavaScript Source Analysis

For each JS file URL discovered:
```bash
curl -sk "<JS_URL>"
```

Search the JS source for:
- API endpoint strings: `/api/`, `/v1/`, `/v2/`, `.json`, `fetch(`, `axios.`, `XMLHttpRequest`
- Authentication patterns: `Authorization:`, `Bearer`, `x-api-key`, `token`
- Parameter names in URLs and request bodies
- GraphQL queries/mutations (look for `query {`, `mutation {`, `gql\``)
- WebSocket URLs: `ws://`, `wss://`, `new WebSocket(`

### 2.3 API Endpoint Discovery

If the target has an API (detected via JS, headers, or common paths):

```bash
# If Swagger/OpenAPI found, fetch it
curl -sk "<TARGET_URL>/swagger.json"
curl -sk "<TARGET_URL>/openapi.json"
curl -sk "<TARGET_URL>/api-docs"
```

Extract all paths, methods, and parameter names from the spec.

If no spec is found, enumerate common API patterns:
```
GET /api/users
GET /api/users/1
GET /api/profile
GET /api/me
POST /api/login
POST /api/register
GET /api/products
GET /api/items
GET /api/orders
GET /api/admin
```

---

## Phase 3: Authentication Mechanism Mapping

### 3.1 Identify Auth Type

Determine how the application authenticates users:

- **Session cookies**: Look for `Set-Cookie` on login response with `HttpOnly`, `Secure` flags
- **JWT tokens**: Look for `Authorization: Bearer eyJ...` pattern in JS or API responses
- **API keys**: Look for `x-api-key`, `api_key` query params, or key-based auth in JS
- **Basic Auth**: Server returns `WWW-Authenticate: Basic`
- **OAuth/OIDC**: Redirects to external provider, `/oauth/`, `/auth/`, `/.well-known/openid-configuration`

### 3.2 Test Login Endpoint

```bash
# Standard form login
curl -sk -X POST "<TARGET_URL>/login" \
  -d "username=admin&password=admin" \
  -D -

# JSON API login
curl -sk -X POST "<TARGET_URL>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' \
  -D -
```

Record: login endpoint, request format (form/JSON), response format, session/token mechanism.

### 3.3 Map Protected vs. Public Endpoints

For each discovered endpoint, test without authentication:
```bash
curl -sk -o /dev/null -w "%{http_code}" "<ENDPOINT_URL>"
```

Classify each endpoint as:
- **Public**: Returns 200 without auth
- **Auth required**: Returns 401 or 302 to login
- **Forbidden**: Returns 403
- **Unknown**: Returns 404 or other

---

## Phase 4: Parameter & Input Surface Mapping

For each endpoint:

1. **URL path parameters**: `/users/{id}`, `/items/{slug}`, `/orders/{order_id}`
2. **Query string parameters**: `?id=1`, `?search=test`, `?page=1&limit=10`
3. **Request body fields**: JSON keys, form field names
4. **HTTP headers**: Custom headers like `X-User-ID`, `X-Forwarded-For`, `X-Real-IP`
5. **Cookie values**: Session IDs, preference values, role/user identifiers

For each parameter, note:
- **Name** of the parameter
- **Type**: numeric ID, string, email, URL, file path, JSON blob
- **Endpoint** it appears on
- **HTTP method** of the request

---

## Output Format

Write all findings to `pentest/target-map.md`:

```markdown
# Target Reconnaissance Map

## Target
- **URL**: <target URL>
- **Date**: <assessment date>

## Technology Stack
- **Server**: [e.g. nginx/1.18]
- **Backend**: [e.g. PHP 8.1, Node.js Express, Django]
- **Frontend**: [e.g. React SPA, server-rendered HTML]
- **Database hints**: [e.g. PostgreSQL via error messages]
- **CDN/WAF**: [e.g. Cloudflare detected]
- **Other indicators**: [e.g. PHPSESSID cookie → PHP]

## Security Headers
| Header | Present | Value |
|--------|---------|-------|
| Content-Security-Policy | Yes/No | [value or N/A] |
| X-Frame-Options | Yes/No | [value] |
| X-Content-Type-Options | Yes/No | [value] |
| Strict-Transport-Security | Yes/No | [value] |
| X-XSS-Protection | Yes/No | [value] |

## Discovered Endpoints

### Public Endpoints (no auth required)
| Method | Path | Parameters | Notes |
|--------|------|------------|-------|
| GET | / | — | Homepage |
| GET | /login | — | Login page |
| POST | /api/login | username, password (JSON) | Returns JWT |

### Authenticated Endpoints
| Method | Path | Parameters | Auth Type | Notes |
|--------|------|------------|-----------|-------|
| GET | /api/users | — | Bearer JWT | Returns user list |
| GET | /api/users/{id} | id (path, numeric) | Bearer JWT | User profile |
| PUT | /api/users/{id} | id (path), name, email (JSON body) | Bearer JWT | Update profile |
| DELETE | /api/users/{id} | id (path, numeric) | Bearer JWT | Delete user |

### Admin / Privileged Endpoints
| Method | Path | Parameters | Notes |
|--------|------|------------|-------|
| GET | /admin | — | Returns 403 to regular users |
| GET | /api/admin/users | — | Admin only - user management |

## Authentication Mechanism
- **Type**: [JWT / Session Cookie / API key / Basic / OAuth]
- **Login endpoint**: `POST /api/login`
- **Token location**: [Authorization: Bearer header / Cookie / query param]
- **Session cookie flags**: [HttpOnly, Secure, SameSite=Strict]
- **Token format**: [JWT with HS256 / opaque session ID / etc.]

## API Specification
- **Swagger/OpenAPI available**: [Yes at /swagger.json / No]
- **GraphQL detected**: [Yes at /graphql / No]

## Parameters of Interest (Prioritized for Testing)

### High-Priority (ID/object reference parameters)
| Endpoint | Parameter | Type | Notes |
|----------|-----------|------|-------|
| GET /api/users/{id} | id | numeric | IDOR candidate |
| GET /api/orders/{id} | id | numeric | IDOR candidate |

### Medium-Priority (string/search parameters)
| Endpoint | Parameter | Type | Notes |
|----------|-----------|------|-------|
| GET /search | q | string | XSS/SQLi candidate |
| POST /api/items | name, description | string | XSS/SQLi candidate |

### Special / High-Risk Parameters
| Endpoint | Parameter | Type | Notes |
|----------|-----------|------|-------|
| GET /download | file | file path | Path traversal / LFI candidate |
| POST /fetch | url | URL | SSRF candidate |
| POST /upload | file | multipart | File upload candidate |

## File Upload Endpoints
| Endpoint | Method | Field Name | Accepted Types (claimed) |
|----------|--------|------------|--------------------------|
| /api/upload | POST | file | image/* |

## Interesting Findings (Passive)
- [Any exposed .env, backup files, verbose error messages, version disclosures]
- [Certificate transparency subdomains found]
- [Admin panels, debug endpoints]

## Subdomains / Related Hosts
- [List any additional subdomains or related hosts discovered]
```

---

## Important Reminders

- Stay within scope: only test the specified target domain and its subdomains.
- Do NOT perform destructive actions during recon (no DELETE requests, no form submissions that modify data).
- Use `-sk` with curl to follow redirects silently and ignore certificate errors for internal testing.
- The target map is the foundation for all subsequent skills — be thorough.
- If the target requires authentication for most endpoints, note any test credentials provided by the user.
- If you discover API documentation (Swagger, OpenAPI, Postman collections), use it to supplement your crawl.
- Flag any especially high-value targets: admin panels, file uploads, URL fetch features, XML import endpoints, and any endpoint accepting `id` parameters.
