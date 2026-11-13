# Area 4 — Cart & Checkout Tampering: step-by-step manual walkthrough

How a tester does this **by hand**, one request at a time, the way the engagement
brief requires (manual, Burp + browser, test mode only). The worked example runs
against the local `cart_lab.py`, and the **same technique** is what you then apply
to `test.myshopapps.com`. Outputs below are the lab's real responses.

> Golden rule of this area: **the server must recompute every price, quantity and
> discount itself.** Every flaw here is the server *trusting a number the client
> sent*. Your whole job is to change that number and see whether the total moves.

---

## 0. Setup (once)

1. Start the target:
   ```bash
   python3 cart_lab.py            # http://127.0.0.1:8003
   ```
2. Point your browser through **Burp** (embedded browser is easiest) and add the
   host to **Target → Scope**.
3. Turn **Proxy → Intercept** on. You'll catch each request, edit it, forward it.
4. Keep `../03-findings-register.md` open — one row per confirmed flaw.

What makes tampering possible here: the add-to-cart request carries the fields the
server trusts:
```
GET /cart/add?product=mug&qty=1&price=10.00
```
In a real Shopify theme/app the equivalent is a cart `/cart/add.js` POST, a hidden
`price`/`amount` form field, or a value in client-side JS the server reads back.
The method is identical: **find the number, change the number.**

---

## 4.1 — Price tampering

**Goal:** pay less than the real price by sending your own `price`.

**Steps**
1. In the browser, add the Blue Mug (real price £10.00) to the cart.
2. In Burp, the request is `GET /cart/add?product=mug&qty=1&price=10.00`.
   Send it to **Repeater** (Ctrl-R) so you can edit and re-send freely.
3. Change `price=10.00` → `price=0.01`, and `qty=1` → `qty=2`. Forward/Send.
4. Open `/cart`.

**Expected if secure:** the mug costs £20.00 — the server ignores your price and
looks it up from the catalogue.

**Observed (vulnerable):**
```
Cart total: £0.02
```
The server used *your* £0.01, not the real £10.00. → **FAIL. Finding.**

**Evidence to capture:** the Repeater request with `price=0.01`, and the `/cart`
response showing £0.02.

---

## 4.2 — Negative / zero quantity

**Goal:** turn a line item into a **credit** by sending a negative quantity.

**Steps**
1. In Repeater, take the add request and set `qty=-3` on the Logo Shirt
   (real £25.00): `GET /cart/add?product=shirt&qty=-3`. Send.
2. Open `/cart` and read the subtotal.

**Expected if secure:** rejected — "quantity must be at least 1".

**Observed (vulnerable):**
```
Subtotal: -£74.98     (the -3 × £25 line is negative, offsetting other items)
Total:    -£74.98
```
A negative line reduces the order total — stack it against a real item and you can
drive the amount you owe **down**. → **FAIL. Finding.**

Also try `qty=0` (free line) and a huge `qty` (integer/stock-logic edge cases).

---

## 4.3 — Discount code reuse & stacking

**Goal:** apply a single-use code more than once, or stack codes, beyond intent.

**Steps** (use a clean cart for a clear number — Clear, then add one shirt £25.00)
1. Apply `SAVE10` (10% off): `GET /discount?code=SAVE10`.
2. Re-send the **same** request two more times.
3. Open `/cart`.

**Expected if secure:** the code applies once; a second attempt is refused
("code already used" / "one code per order").

**Observed (vulnerable):** the cart shows **Discounts (3)** — the same code took
effect three times, compounding the reduction. Against the tampered cart above the
engine even produced a **negative discount floor** with no guard. → **FAIL. Finding.**

Variations to try by hand: two *different* codes together (`SAVE10` + `FIVEOFF`),
and re-ordering add/discount requests to see if the discount is recomputed.

---

## 4.4 — Totals / rounding / final-charge check

**Goal:** confirm the tampered total actually reaches **checkout**, not just the
cart preview.

**Steps**
1. With a tampered cart (e.g. the £0.01 mug, or stacked discounts), open
   `/checkout` (test mode / Bogus Gateway).
2. Read the **Charged** figure.

**Observed (vulnerable):**
```
⚠ Order total is £0 or negative — the store would ship for free / owe the buyer.
Charged: -£52.49
```
The flawed total carries all the way to the charge step. On a real store you would
confirm (in **test mode only**) that the order *completes* at the tampered amount —
that's the difference between a cart-display bug and a real financial finding.
→ **FAIL. Finding.**

---

## Reproduce it all in one shot (sanity check)

```bash
B=http://127.0.0.1:8003 ; J=/tmp/cart.cookies ; rm -f $J
curl -s -c $J -b $J "$B/cart/add?product=mug&qty=2&price=0.01" >/dev/null   # 4.1
curl -s -b $J "$B/cart/add?product=shirt&qty=-3" >/dev/null                 # 4.2
for i in 1 2 3; do curl -s -b $J "$B/discount?code=SAVE10" >/dev/null; done # 4.3
curl -s -b $J "$B/checkout" | grep -Eo 'Charged.*|Order total.*'            # 4.4
```
(The mobile lab at the Cart-Lab artifact does the same with an on-screen "intercept"
panel if you don't have Burp to hand.)

---

## Doing this on `test.myshopapps.com` (the real target)

Same method, within the rules:

- **Find the number.** Watch the real add-to-cart / cart-update / checkout requests
  in Burp. Look for `price`, `amount`, `quantity`, a line-item total, or any discount
  value in the request body, query string, or a hidden form field.
- **Change one number at a time** in Repeater; never run an automated scanner here.
- **Test mode only.** Confirm Bogus Gateway / test cards are on before checkout. If
  it isn't, stop and ask the owner.
- **Scope rule #3.** You're testing *your* cart/theme/custom-app logic. If a flaw
  only works because of Shopify's own checkout rails, **stop and report it** — don't
  keep probing Shopify's platform.
- **Record** each confirmed flaw in `../03-findings-register.md` with the tampered
  request, the resulting total, and a severity from `../05-severity-guide.md`
  (price-to-zero that *completes* an order is typically High/Critical).

## The fix (for the report)

| Flaw | Fix |
|------|-----|
| 4.1 Price tampering | Recompute every line price server-side from the catalogue; ignore any client-supplied price. |
| 4.2 Negative/zero qty | Validate `quantity >= 1` (integer) server-side before it touches totals. |
| 4.3 Discount reuse/stack | Enforce usage limits and stacking rules server-side, per order, at redemption time. |
| 4.4 Totals | Derive the final charge from trusted server data only; floor discounts at the subtotal; never trust a client total. |
