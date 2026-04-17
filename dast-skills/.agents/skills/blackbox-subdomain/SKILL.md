---
name: blackbox-subdomain
description: >-
  Actively test a target domain for subdomain takeover vulnerabilities using
  blackbox techniques. Reads pentest/target-map.md for known subdomains,
  performs additional subdomain enumeration via certificate transparency and
  DNS brute-force, checks each subdomain for dangling DNS records pointing to
  unclaimed cloud services (GitHub Pages, Heroku, AWS S3, Azure, Netlify,
  Fastly, etc.), and verifies takeover potential. Writes confirmed findings to
  pentest/subdomain-results.md.
---

# Blackbox Subdomain Takeover Detection

You are actively testing a target domain for subdomain takeover vulnerabilities without source code access. A subdomain takeover occurs when a DNS record points to an external service that is no longer in use — allowing an attacker to claim that service and serve content under the target's subdomain.

**Prerequisite**: Read `pentest/target-map.md` for any known subdomains.

---

## What Is a Subdomain Takeover

1. `sub.target.com` has a CNAME → `target.someservice.com`
2. `target.someservice.com` no longer exists (service was deleted)
3. Attacker creates `target.someservice.com` on the service → now controls `sub.target.com`

---

## Phase 1: Subdomain Discovery

### Method 1: Certificate Transparency Logs

```bash
DOMAIN="target.com"  # Replace with actual target domain

# Query crt.sh for all certificates issued for this domain
curl -sk "https://crt.sh/?q=%25.$DOMAIN&output=json" | \
  python3 -c "import json,sys; data=json.load(sys.stdin); [print(e['name_value']) for e in data]" 2>/dev/null | \
  sort -u | grep -v '*' | grep "$DOMAIN"
```

### Method 2: DNS Brute Force (Common Subdomains)

```bash
DOMAIN="target.com"

SUBDOMAINS="www api admin dev staging prod test mail smtp pop imap ftp ssh vpn remote 
  app cdn static assets media images files download upload docs wiki help support 
  blog news portal dashboard beta alpha v1 v2 api-v1 api-v2 mobile app-api 
  auth login sso oauth identity accounts payments billing shop store
  status metrics monitor grafana kibana jenkins ci cd deploy qa uat
  s3 assets-s3 bucket media-bucket content-bucket"

for SUB in $SUBDOMAINS; do
  RESULT=$(dig +short "$SUB.$DOMAIN" 2>/dev/null | head -3)
  if [ -n "$RESULT" ]; then
    echo "FOUND: $SUB.$DOMAIN → $RESULT"
  fi
done
```

### Method 3: Check for Wildcard DNS

```bash
# Check if wildcard DNS is configured (would make individual results unreliable)
dig +short "nonexistent12345.$DOMAIN"
# If this returns an IP → wildcard DNS configured → results unreliable
```

---

## Phase 2: CNAME Fingerprinting

For each discovered subdomain, check if it has a CNAME record pointing to an external service:

```bash
for SUB in $(cat /tmp/found_subdomains.txt); do
  CNAME=$(dig +short CNAME "$SUB" 2>/dev/null)
  if [ -n "$CNAME" ]; then
    echo "$SUB → CNAME → $CNAME"
  fi
done
```

**Takeover-prone services to look for in CNAME targets**:

| Service | CNAME Pattern | Takeover Signal |
|---------|----------|---------|
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" |
| Heroku | `*.herokudns.com`, `*.herokussl.com` | "No such app" |
| AWS S3 | `*.s3.amazonaws.com`, `s3-website-*.amazonaws.com` | "NoSuchBucket" |
| AWS Elastic Beanstalk | `*.elasticbeanstalk.com` | "HTTP 404" with AWS styling |
| Azure | `*.azurewebsites.net`, `*.cloudapp.net` | "Azure Error" |
| Netlify | `*.netlify.app` | "Not Found - Request ID..." |
| Fastly | `*.fastly.net` | "Fastly error: unknown domain" |
| Ghost | `*.ghost.io` | "404 - Unknown site" |
| Shopify | `*.myshopify.com` | "Sorry, this shop is currently unavailable" |
| Tumblr | `*.tumblr.com` | "There's nothing here" (unclaimed) |
| Pantheon | `*.pantheonsite.io` | "404 — Site Not Found" |
| Surge.sh | `*.surge.sh` | "project not found" |
| ReadTheDocs | `*.readthedocs.io` | "404 Not Found" |
| Cargo | `*.cargo.site` | unclaimed page |
| HubSpot | `*.hubspot.net` | "This page doesn't exist" |
| Zendesk | `*.zendesk.com` | "Help Center Closed" |
| Firebase | `*.firebaseapp.com` | "404 — No app" |
| Bitbucket | `*.bitbucket.io` | "Repository not found" |

---

## Phase 3: Verify Takeover Potential

For each CNAME pointing to an external service, verify the takeover error:

```bash
# Test if the service returns a "not found" / "unclaimed" error
curl -sk "http://dangling-sub.target.com" | head -20
curl -sk "https://dangling-sub.target.com" | head -20

# Check AWS S3 specifically
curl -sk "http://dangling-sub.target.com" | grep -i "NoSuchBucket\|NoSuchKey"

# Check GitHub Pages
curl -sk "https://dangling-sub.target.com" | grep -i "github\|404\|not found"

# Check Heroku
curl -sk "https://dangling-sub.target.com" | grep -i "heroku\|no such app"
```

**Confirmed takeover-vulnerable** if:
1. The CNAME points to an unclaimed service endpoint
2. The service returns its "domain not configured" error message
3. You can verify the service allows free registration of that specific endpoint

---

## Phase 4: NS & MX Takeover

Check NS and MX records too:

```bash
# Check if NS records point to an unused zone
dig NS target.com
# If NS points to a provider where the zone was deleted → NS takeover possible

# Check MX records
dig MX target.com
```

---

## Phase 5: Assess Exploitability

For a confirmed takeover, determine what an attacker could do:

1. **Cookie theft / Session hijacking**: If `sub.target.com` cookie scope matches `*.target.com`, attacker can serve JS from `sub.target.com` to steal cookies.
2. **CSP bypass**: If target.com's CSP allows `*.target.com` as a script source, attacker can run scripts on main domain.
3. **OAuth redirect_uri abuse**: If the OAuth app allows `sub.target.com` as a redirect URI, attacker can steal auth codes.
4. **Phishing**: Serve a convincing clone from a trusted target subdomain.

---

## Output Format

Write findings to `pentest/subdomain-results.md`:

```markdown
# Subdomain Takeover Assessment Results

## Summary
- Subdomains discovered: [N]
- CNAME records checked: [N]
- Confirmed takeover-vulnerable: [N]

## Discovered Subdomains
| Subdomain | Record Type | Points To | Status |
|-----------|------------|-----------|--------|
| api.target.com | A | 1.2.3.4 | Active |
| staging.target.com | CNAME | target-staging.herokudns.com | ⚠️ Potentially unclaimed |
| old.target.com | CNAME | target-bucket.s3.amazonaws.com | 🔴 VULNERABLE |

## Findings

### [CRITICAL] old.target.com — AWS S3 Subdomain Takeover

- **Subdomain**: `old.target.com`
- **DNS**: `old.target.com` CNAME → `target-legacy-assets.s3.amazonaws.com`
- **Status**: S3 bucket `target-legacy-assets` does not exist (returns `NoSuchBucket`)
- **Takeover Impact**:
  - Attacker can create S3 bucket named `target-legacy-assets` in any AWS account
  - Serve arbitrary content from `old.target.com` under the trusted target.com domain
  - If CSP includes `*.target.com` → XSS on main domain
  - Steal OAuth codes if redirect URIs include `old.target.com`
- **Evidence**:
  ```bash
  dig +short CNAME old.target.com
  # → target-legacy-assets.s3.amazonaws.com.

  curl -sk http://old.target.com
  # → <Error><Code>NoSuchBucket</Code><BucketName>target-legacy-assets</BucketName></Error>
  ```
- **Remediation**: Remove the dangling CNAME record for `old.target.com` from DNS immediately. If the subdomain is still needed, re-create the S3 bucket and configure it properly before removing the DNS record.

### [HIGH] staging.target.com — Heroku DNS Dangling

- **DNS**: `staging.target.com` CNAME → `target-staging-app.herokudns.com`
- **Status**: Heroku returns "No such app" — app may have been deleted
- **Remediation**: Remove the CNAME record or re-create the Heroku app and add the custom domain.
```

---

## Important Reminders

- Do NOT actually claim the subdomain during assessment — document the vulnerability only.
- Certificate transparency logs (crt.sh) are the most comprehensive source of subdomains.
- Wildcard DNS (`*.target.com → 1.2.3.4`) means no individual results are meaningful.
- Subdomain takeover severity depends on the cookie/CSP/OAuth scope impact.
- Clean up: write directly to `pentest/subdomain-results.md`.
