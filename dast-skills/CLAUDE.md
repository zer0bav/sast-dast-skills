# Blackbox Web Penetration Test (DAST)

Your goal is to perform a **blackbox** security assessment against a target URL/domain provided by the user. You have no access to source code — all testing is done through active HTTP requests.

**TARGET:** [User will provide the target URL in the prompt]

---

## Step 1: Reconnaissance & Endpoint Mapping

Before running vulnerability checks, check if `pentest/target-map.md` already exists. If it does, skip this step.

Run the `blackbox-recon` skill directly (this one stays in-session since all later steps depend on reading the mapped endpoints and attack surface).

**Wait for this step to finish before proceeding.**

---

## Step 2: Active Vulnerability Detection (Parallel)

Run all active payload tests at the same time. Skip any task where the output file already exists.

- Skip IDOR if `pentest/idor-results.md` already exists.
- Skip SQLi if `pentest/sqli-results.md` already exists.
- Skip NoSQLi if `pentest/nosqli-results.md` already exists.
- Skip SSRF if `pentest/ssrf-results.md` already exists.
- Skip XSS if `pentest/xss-results.md` already exists.
- Skip SSTI if `pentest/ssti-results.md` already exists.
- Skip RCE if `pentest/rce-results.md` already exists.
- Skip XXE if `pentest/xxe-results.md` already exists.
- Skip LFI if `pentest/lfi-results.md` already exists.
- Skip File Upload if `pentest/fileupload-results.md` already exists.
- Skip Auth Bypass if `pentest/auth-bypass-results.md` already exists.
- Skip JWT if `pentest/jwt-results.md` already exists.
- Skip CSRF if `pentest/csrf-results.md` already exists.
- Skip CORS if `pentest/cors-results.md` already exists.
- Skip Open Redirect if `pentest/redirect-results.md` already exists.
- Skip CRLF if `pentest/crlf-results.md` already exists.
- Skip Business Logic if `pentest/businesslogic-results.md` already exists.
- Skip GraphQL if `pentest/graphql-results.md` already exists.
- Skip WebSocket if `pentest/websocket-results.md` already exists.
- Skip Subdomain Takeover if `pentest/subdomain-results.md` already exists.
- Skip Info Disclosure if `pentest/infodisclosure-results.md` already exists.

Start **one subagent per check**, all **in parallel**, each with a dedicated task. Give each subagent the same instruction pattern:

> Read `pentest/target-map.md` for context and endpoints. Then, run the named blackbox skill to actively test those endpoints (inject payloads, fuzz parameters). Write all validated findings and proofs-of-concept (PoCs) to that skill's results file. Clean up any intermediate recon files for that skill when done.

| Skill | Results file | Typical intermediate files to clean |
|-------|----------------|--------------------------------------|
| blackbox-idor | `pentest/idor-results.md` | `pentest/idor-recon.md` |
| blackbox-sqli | `pentest/sqli-results.md` | `pentest/sqli-recon.md`, `pentest/sqli-batch-*.md` |
| blackbox-nosqli | `pentest/nosqli-results.md` | — |
| blackbox-ssrf | `pentest/ssrf-results.md` | `pentest/ssrf-recon.md` |
| blackbox-xss | `pentest/xss-results.md` | `pentest/xss-recon.md` |
| blackbox-ssti | `pentest/ssti-results.md` | `pentest/ssti-recon.md` |
| blackbox-rce | `pentest/rce-results.md` | `pentest/rce-recon.md` |
| blackbox-xxe | `pentest/xxe-results.md` | `pentest/xxe-recon.md` |
| blackbox-lfi | `pentest/lfi-results.md` | `pentest/lfi-recon.md` |
| blackbox-fileupload | `pentest/fileupload-results.md` | `pentest/fileupload-recon.md` |
| blackbox-auth | `pentest/auth-bypass-results.md` | `pentest/auth-recon.md` |
| blackbox-jwt | `pentest/jwt-results.md` | — |
| blackbox-csrf | `pentest/csrf-results.md` | `pentest/csrf-recon.md` |
| blackbox-cors | `pentest/cors-results.md` | — |
| blackbox-redirect | `pentest/redirect-results.md` | `pentest/redirect-recon.md` |
| blackbox-crlf | `pentest/crlf-results.md` | — |
| blackbox-business | `pentest/businesslogic-results.md` | `pentest/businesslogic-threats.md` |
| blackbox-graphql | `pentest/graphql-results.md` | `pentest/graphql-recon.md` |
| blackbox-websocket | `pentest/websocket-results.md` | `pentest/websocket-recon.md` |
| blackbox-subdomain | `pentest/subdomain-results.md` | — |
| blackbox-infodisclosure | `pentest/infodisclosure-results.md` | — |

Wait for all subagents to finish before proceeding.

---

## Step 3: Report Generation

After all subagents from Step 2 finish, generate the final consolidated report.

Skip this step if `pentest/final-report.md` already exists.

Launch a single subagent:

> Read all available `pentest/*-results.md` files and `pentest/target-map.md` for context. Then, run the `blackbox-report` skill to create `pentest/final-report.md` with all verified vulnerabilities, reproducible PoC steps, and severity rankings.
