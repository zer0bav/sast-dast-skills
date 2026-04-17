# LLM Security Skills — SAST + DAST

A collection of agent skills that turn your LLM coding assistant into a fully functional **security assessment toolkit** — covering both **Static Application Security Testing (SAST)** for source code analysis and **Dynamic Application Security Testing (DAST)** for blackbox penetration testing. Works natively with Claude Code, Opencode, Cursor, Codex, and any other assistant that supports agent skills. No third-party tools or API keys required.

![Process in Claude Code](demo.gif)

---

## Overview

This repo ships two independent toolkits that can be used separately or together:

| Toolkit | Folder | Use Case |
|---------|--------|----------|
| **SAST Skills** | `sast-files/` | You have source code access — find vulnerabilities via static analysis |
| **DAST Skills** | `dast-skills/` | No source code — blackbox pentest a live target URL |

---

## SAST Toolkit — Source Code Analysis

### How It Works

Open `sast-files/` as your workspace in your AI coding assistant. The orchestration file (`CLAUDE.md` or `AGENTS.md`) runs the full assessment automatically in three steps:

1. **Codebase Analysis** — The `sast-analysis` skill maps the technology stack, architecture, entry points, data flows, and trust boundaries. Writes to `sast/architecture.md`.

2. **Vulnerability Detection (parallel)** — All 13 detection skills run in parallel as subagents. Each follows a two-phase approach: recon to find candidate locations, then verification to confirm exploitability. Results go to `sast/*-results.md`.

3. **Report Generation** — The `sast-report` skill consolidates all findings into `sast/final-report.md`, ranked by severity with remediation guidance.

### Installation

Copy your project into `sast-files/`, then open that folder as your workspace:

```bash
cp -r /path/to/your/project sast-files/
```

> **Note:** If your project already has a `CLAUDE.md` or `AGENTS.md`, remove it first — it will conflict with the orchestration file.

### Usage

Open the workspace and ask your agent:

```
Run vulnerability scan
```

or

```
Find vulnerabilities in this codebase
```

### SAST Skills

| Skill | Vulnerability Class |
|-------|---------------------|
| `sast-analysis` | Codebase recon, architecture mapping, threat modeling |
| `sast-sqli` | SQL Injection |
| `sast-xss` | Cross-Site Scripting (reflected, stored, DOM) |
| `sast-ssrf` | Server-Side Request Forgery |
| `sast-rce` | Remote Code Execution (command injection, eval, unsafe deserialization) |
| `sast-idor` | Insecure Direct Object Reference |
| `sast-xxe` | XML External Entity Injection |
| `sast-ssti` | Server-Side Template Injection |
| `sast-jwt` | Insecure JWT implementations |
| `sast-missingauth` | Missing authentication & broken function-level authorization |
| `sast-pathtraversal` | Path / directory traversal |
| `sast-fileupload` | Insecure file upload |
| `sast-businesslogic` | Business logic flaws (price manipulation, race conditions, workflow bypass) |
| `sast-graphql` | GraphQL injection |
| `sast-report` | Consolidated final report ranked by severity |

### SAST Output

| File | Description |
|------|-------------|
| `sast/architecture.md` | Technology stack, entry points, data flows |
| `sast/*-results.md` | Per-class findings with proof-of-concept and remediation |
| `sast/final-report.md` | Consolidated report ranked by severity |

---

## DAST Toolkit — Blackbox Pentest

The DAST toolkit performs active security testing against a **live target URL** without any source code access. It uses `curl`, DNS lookups, WebSocket clients, and manual payload crafting to discover and confirm vulnerabilities end-to-end.

### How It Works

Open `dast-skills/` as your workspace, then tell your agent the target URL. The orchestration file runs the full pentest in three steps:

1. **Reconnaissance** — The `blackbox-recon` skill crawls the target, fingerprints the technology stack, discovers all endpoints and parameters, maps authentication mechanisms, and writes everything to `pentest/target-map.md`.

2. **Active Vulnerability Detection (parallel)** — All 21 detection skills run simultaneously as subagents. Each reads the target map, injects payloads, and writes confirmed findings with PoC `curl` commands to `pentest/*-results.md`.

3. **Report Generation** — The `blackbox-report` skill consolidates everything into `pentest/final-report.md` with severity rankings, PoC steps, and remediation guidance.

### Usage

Open `dast-skills/` as your workspace and ask:

```
Pentest https://target.com
```

or

```
Find vulnerabilities in https://target.com — run the full blackbox pentest
```

> **Important:** Only use this toolkit against targets you own or have explicit written permission to test. Unauthorized security testing is illegal.

### DAST Skills

| Skill | Vulnerability Class |
|-------|---------------------|
| `blackbox-recon` | Target mapping, endpoint discovery, tech fingerprinting |
| `blackbox-sqli` | SQL Injection (error-based, boolean-blind, time-based, union) |
| `blackbox-nosqli` | NoSQL Injection (MongoDB `$ne`, `$where`, regex exfiltration) |
| `blackbox-xss` | XSS (reflected, stored, DOM-based, bypass techniques) |
| `blackbox-ssti` | Server-Side Template Injection (Jinja2, Twig, FreeMarker, ERB, Mako, Velocity) |
| `blackbox-ssrf` | SSRF (cloud metadata, internal network, OOB detection) |
| `blackbox-rce` | RCE (OS command injection, deserialization, eval injection) |
| `blackbox-xxe` | XXE (file read, SSRF, OOB exfiltration, SVG upload, XInclude) |
| `blackbox-lfi` | LFI / Path Traversal (encoding bypass, PHP wrappers, log poisoning) |
| `blackbox-fileupload` | Insecure File Upload (extension bypass, webshell upload, magic bytes) |
| `blackbox-idor` | IDOR (horizontal & vertical privilege escalation, sequential ID enum) |
| `blackbox-auth` | Auth Bypass (JWT alg:none, default creds, missing auth, vertical escalation) |
| `blackbox-jwt` | JWT (alg confusion, weak secret brute-force, kid/jku injection) |
| `blackbox-csrf` | CSRF (missing token, SameSite bypass, null origin, JSON CSRF) |
| `blackbox-cors` | CORS Misconfiguration (reflected origin + credentials, null origin, subdomain trust) |
| `blackbox-redirect` | Open Redirect (protocol bypass, OAuth redirect_uri manipulation) |
| `blackbox-crlf` | CRLF Injection / HTTP Response Splitting |
| `blackbox-business` | Business Logic (price manipulation, coupon abuse, race conditions, workflow bypass) |
| `blackbox-graphql` | GraphQL (introspection, batching attacks, injection, missing auth on resolvers) |
| `blackbox-websocket` | WebSocket Security (CSWSH, missing auth, injection via messages) |
| `blackbox-subdomain` | Subdomain Takeover (dangling DNS, crt.sh enum, service fingerprinting) |
| `blackbox-infodisclosure` | Info Disclosure (.env, .git, debug endpoints, verbose errors, Spring Actuator) |
| `blackbox-report` | Consolidated final report with PoC, severity rankings, remediation |

### DAST Output

All output is written to a `pentest/` folder inside your workspace:

| File | Description |
|------|-------------|
| `pentest/target-map.md` | Full attack surface map — endpoints, parameters, auth, tech stack |
| `pentest/*-results.md` | Per-skill confirmed findings with `curl` PoC commands |
| `pentest/final-report.md` | Consolidated pentest report ranked by severity |

---

## Supported Assistants

Both toolkits support any AI coding assistant with file-based agent skill support:

| Assistant | File to use |
|-----------|-------------|
| **Claude Code** | `CLAUDE.md` |
| **Opencode** | `AGENTS.md` |
| **Cursor** | `AGENTS.md` |
| **Codex CLI** | `AGENTS.md` |
| **Any other MCP/agent-compatible IDE** | `AGENTS.md` |

Claude Code with an Opus-class model is recommended for best results, especially on the DAST toolkit where agentic reasoning quality directly affects finding precision.

---

## Repo Structure

```
.
├── README.md
├── demo.gif
│
├── sast-files/                  # SAST toolkit (source code analysis)
│   ├── CLAUDE.md                # Claude Code orchestration
│   ├── AGENTS.md                # Opencode / Cursor orchestration
│   └── .agents/skills/
│       ├── sast-analysis/
│       ├── sast-sqli/
│       ├── sast-xss/
│       ├── sast-ssrf/
│       ├── sast-rce/
│       ├── sast-idor/
│       ├── sast-xxe/
│       ├── sast-ssti/
│       ├── sast-jwt/
│       ├── sast-missingauth/
│       ├── sast-pathtraversal/
│       ├── sast-fileupload/
│       ├── sast-businesslogic/
│       ├── sast-graphql/
│       └── sast-report/
│
└── dast-skills/                 # DAST toolkit (blackbox pentest)
    ├── CLAUDE.md                # Claude Code orchestration
    ├── AGENTS.md                # Opencode / Cursor orchestration
    └── .agents/skills/
        ├── blackbox-recon/
        ├── blackbox-sqli/
        ├── blackbox-nosqli/
        ├── blackbox-xss/
        ├── blackbox-ssti/
        ├── blackbox-ssrf/
        ├── blackbox-rce/
        ├── blackbox-xxe/
        ├── blackbox-lfi/
        ├── blackbox-fileupload/
        ├── blackbox-idor/
        ├── blackbox-auth/
        ├── blackbox-jwt/
        ├── blackbox-csrf/
        ├── blackbox-cors/
        ├── blackbox-redirect/
        ├── blackbox-crlf/
        ├── blackbox-business/
        ├── blackbox-graphql/
        ├── blackbox-websocket/
        ├── blackbox-subdomain/
        ├── blackbox-infodisclosure/
        └── blackbox-report/
```

---

## Tips

- **Skip completed steps**: Both toolkits check if output files already exist before running. Re-running after a partial scan or a fix will only redo the missing parts.
- **Provide test credentials**: For DAST, if the target requires login, include credentials in your initial prompt — e.g. `"Pentest https://target.com — test credentials: admin / admin123"`.
- **Scope control**: The recon skill stays in-scope by default (same domain). Note any additional target subdomains in your prompt if they are in scope.
- **OOB detection**: Some DAST skills (SSRF, XXE, blind SQLi) reference out-of-band detection URLs. Set up a free [webhook.site](https://webhook.site) or [interactsh](https://app.interactsh.com) instance and include the URL in your prompt for blind vulnerability detection.

---

## Legal Disclaimer

This toolkit is provided for **authorized security testing and educational purposes only**. Using it against systems you do not own or have explicit written permission to test is illegal and unethical. The authors assume no liability for any misuse.
