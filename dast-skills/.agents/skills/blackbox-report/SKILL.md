---
name: blackbox-report
description: >-
  Generate a comprehensive, professional blackbox penetration test report by
  consolidating all finding files from pentest/*-results.md and
  pentest/target-map.md. Organizes findings by severity (Critical, High,
  Medium, Low, Informational), provides executive summary with risk overview,
  includes full PoC steps for each finding, and writes the final report to
  pentest/final-report.md. Use as the last step after all blackbox scanning
  skills have completed.
---

# Blackbox Pentest Report Generator

You are generating the final penetration test report. You will consolidate all findings from individual skill result files into a professional, structured report.

**Prerequisite**: Read all available `pentest/*-results.md` files and `pentest/target-map.md`.

---

## Step 1: Collect All Findings

Read every available results file:
- `pentest/target-map.md` — target info and scope
- `pentest/sqli-results.md`
- `pentest/xss-results.md`
- `pentest/ssrf-results.md`
- `pentest/idor-results.md`
- `pentest/rce-results.md`
- `pentest/xxe-results.md`
- `pentest/lfi-results.md`
- `pentest/fileupload-results.md`
- `pentest/auth-bypass-results.md`
- `pentest/businesslogic-results.md`
- `pentest/graphql-results.md`

For each file that exists, extract all confirmed and likely findings.

---

## Step 2: Severity Classification

Classify each finding using CVSS-informed severity:

| Severity | Description | Examples |
|----------|-------------|---------|
| **Critical** | Direct system/data compromise, no user interaction | RCE, SQLi with DB exfiltration, SSRF to metadata/IAM, auth bypass → admin |
| **High** | Significant data exposure or privilege escalation | Stored XSS, IDOR on sensitive data, LFI reading /etc/passwd, file upload webshell |
| **Medium** | Limited data exposure, requires user interaction or specific conditions | Reflected XSS, SSRF blind, XXE blind OOB, weak JWT secret, missing auth on non-sensitive endpoints |
| **Low** | Minimal impact, informational | Missing headers, account enumeration, verbose error messages, introspection enabled |
| **Informational** | Not a vulnerability but worth noting | Technology stack disclosure, server version in headers |

---

## Step 3: Generate Report

Write the complete report to `pentest/final-report.md`:

```markdown
# Penetration Test Report
**Target**: [from target-map.md]
**Assessment Type**: Blackbox / DAST
**Date**: [current date]
**Classification**: Confidential

---

## Executive Summary

[2-3 paragraph high-level summary:]
- What was tested and what methodology was used
- Overall risk posture (Critical/High/Medium risks found)
- Top 3 most critical findings
- General recommendation (e.g. "Immediate remediation required for X and Y before deployment")

### Risk Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | N |
| 🟠 High | N |
| 🟡 Medium | N |
| 🔵 Low | N |
| ℹ️ Informational | N |
| **Total** | **N** |

---

## Target Information

- **Target URL**: [URL]
- **Technology Stack**: [from target-map.md]
- **Authentication**: [mechanism]
- **Scope**: [domains/paths in scope]

---

## Methodology

This assessment was performed as a blackbox penetration test — no source code access. Testing covered:

1. **Reconnaissance**: Target mapping, technology fingerprinting, endpoint discovery
2. **Injection Testing**: SQL injection, OS command injection, template injection
3. **Client-Side Security**: XSS (reflected, stored, DOM-based)
4. **Access Control**: IDOR, missing authentication, privilege escalation, JWT vulnerabilities
5. **Server-Side**: SSRF, XXE, LFI/path traversal, file upload
6. **Business Logic**: Price manipulation, race conditions, workflow bypass
7. **API Security**: GraphQL introspection, batching attacks, auth on resolvers

---

## Findings

[For each confirmed finding, sorted by severity (Critical first):]

### FINDING-001: [SHORT TITLE]

| Field | Value |
|-------|-------|
| **Severity** | 🔴 Critical |
| **Category** | [e.g. SQL Injection / RCE / IDOR / XSS] |
| **Endpoint** | `METHOD /path` |
| **CVSS Score** | [estimate e.g. 9.8] |

**Description**

[Clear description of the vulnerability — what it is, why it exists at this application level (based on evidence), and what makes it exploitable.]

**Impact**

[Concrete impact: what an attacker can do. Use specific examples: "An attacker can read all user records from the database, including email addresses, password hashes, and payment history."]

**Steps to Reproduce**

```bash
# Step 1: [description]
curl -sk ...

# Step 2: [description]
curl -sk ...

# Expected result: [what you observe that proves exploitability]
```

**Evidence**

[Screenshot or response snippet showing the vulnerability — describe what was observed: response code, response body contents, timing, OOB callback received, etc.]

**Remediation**

[Specific, actionable fix. Not just "use parameterized queries" — explain WHERE in the code or what pattern to apply:]
- Primary fix: [most important change]
- Defense in depth: [additional hardening]
- Reference: [OWASP link or CWE if relevant]

---

[Repeat for all findings]

---

## Security Observations (Non-Findings)

[Items that are not vulnerabilities but worth noting:]

### Missing Security Headers
- `Content-Security-Policy`: Not set → increases XSS impact
- `X-Frame-Options`: Not set → clickjacking possible
- `Strict-Transport-Security`: Not set → downgrades possible

### Informational
- Server version disclosed in `Server` header: `nginx/1.18.0`
- Technology stack identifiable via `X-Powered-By: PHP/8.1`

---

## Remediation Priority

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| 1 | FINDING-001: [title] | Low | Critical |
| 2 | FINDING-002: [title] | Medium | High |
| 3 | FINDING-003: [title] | Low | High |
| ... | ... | ... | ... |

---

## Appendix

### Tools & Techniques Used
- `curl` — HTTP request crafting and response analysis
- Manual payload injection and response analysis
- Out-of-band detection (webhook.site / interactsh for SSRF/XXE/blind injection)

### References
- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- CWE Top 25: https://cwe.mitre.org/top25/
```

---

## Important Reminders

- Severity must reflect actual exploitability, not just theoretical risk.
- Every finding MUST include a working PoC or reproduction steps.
- "Likely vulnerable" findings from individual skills should be marked as Medium unless you have confirmation.
- The executive summary should be understandable by a non-technical reader.
- Remediation should be specific to the technology stack identified in target-map.md.
- Do NOT include findings that were "Not Vulnerable" in the individual skill reports.
