# 02 — Test Playbook

Work top to bottom, one test case at a time. Each case has: **goal → steps →
payloads/inputs → PASS (secure) vs FAIL (vuln) → evidence to capture**. When a
case FAILs, open a row in `03-findings-register.md` before moving on.

Legend: `[A]` = act as User A, `[B]` = User B, `[anon]` = logged out.

---

## Area 1 — Authentication (login, signup, password reset)

### 1.1 Weak password policy
- **Goal:** can you register / change to a trivially weak password?
- **Steps:** at signup and at "change password", try `123456`, `password`,
  `test`, the email local-part itself, a 1-char password.
- **FAIL:** any of these is accepted. **PASS:** rejected with a clear policy
  (length + complexity or a breached-password check).
- **Capture:** request + response for the weakest accepted password.

### 1.2 Username / email enumeration
- **Goal:** can an outsider tell whether an email has an account?
- **Steps:** compare responses for a **known-registered** email vs a
  **random-unregistered** email at three places:
  - Login (wrong password): does it say "no account" vs "wrong password"?
  - Signup: does it say "email already in use"?
  - Password reset: does it say "sent" for one and "not found" for the other?
- **Also check:** response **timing** differences and HTTP status/length deltas
  (use Burp Comparer), not just the visible text.
- **FAIL:** responses differ in a way that reveals existence. **PASS:** uniform
  "if an account exists, we've emailed you" style response, same timing/length.
- **Capture:** the two responses side by side (Comparer diff).

### 1.3 Password-reset link: expiry & reuse
- **Goal:** do reset links expire, are they single-use, are they
  unpredictable/bound to the user?
- **Steps:**
  1. Trigger a reset for `[A]`, grab the link from the inbox.
  2. **Reuse:** use it once to reset, then try the same link again.
  3. **Expiry:** request a fresh link, wait past the claimed TTL (e.g. leave it
     an hour+), then try it.
  4. **Invalidation:** request link #1, then request link #2; does #1 still work?
  5. **Token quality:** inspect the token — is it long/random, or guessable
     (sequential, base64 of the user id/email, a timestamp)?
- **FAIL:** link reusable after use, never expires, old link still valid after a
  new one is issued, or token is predictable/not bound to the account.
- **Capture:** the token value(s), the before/after responses.

### 1.4 Session & logout hygiene (quick checks)
- After logout, replay an authenticated request from before logout in Repeater —
  does the old session cookie still work? (**FAIL** if yes.)
- Inspect the session cookie flags: `Secure`, `HttpOnly`, `SameSite`. Missing
  `HttpOnly`/`Secure` on a session cookie → finding.
- **Note:** if the session is a core **Shopify** customer session, this is likely
  platform behaviour → apply rule #3 (report, don't keep probing).

---

## Area 2 — Access control (IDOR / broken object-level authz)

This is the highest-value area. The test is always the same shape: **[A] tries to
read/modify [B]'s object by changing an identifier.**

### 2.1 Orders
- **Steps:** `[A]` opens their own order (note the URL/param, e.g.
  `/account/orders/<id>` or an order token). In Repeater, swap the id/token for
  `[B]`'s order id/token while keeping `[A]`'s session cookie.
- **Try:** sequential ids (`1001 → 1002`), the raw numeric customer/order id, and
  the order's confirmation token if one is used.
- **FAIL:** `[A]` sees `[B]`'s order details. **PASS:** 403/404/redirect to login,
  or "not found".
- **Capture:** request with swapped id + the response proving cross-account read.

### 2.2 Account / profile
- Same pattern on account endpoints: profile view/edit, saved addresses, stored
  details. Swap `customer_id` / account slug in URL, body, or hidden form field.
- **FAIL:** read or **edit** of another account.

### 2.3 Custom-app endpoints & app proxy (`/apps/*`)
- Your custom apps are prime IDOR territory because they often roll their own
  authz. For each custom-app route that takes an id (order id, customer id,
  record id, `?shop=`, `?id=`):
  - Remove the id → does it default to "all" / someone else?
  - Increment/guess the id as `[A]` → do you get `[B]`'s record?
  - Call it **`[anon]`** (no session) → does it still return data?
  - Tamper with any signature/HMAC param — does the app actually verify it, or
    accept the request when you change `id` but leave the old signature?
- **FAIL:** any cross-tenant/cross-customer data, or data without a valid session.
- **Capture:** the route, the parameter changed, the leaked response.

### 2.4 Forced browsing to privileged views
- As `[anon]` and as a normal customer `[A]`, try to reach any admin-ish or
  internal pages your theme/app exposes (e.g. `/apps/<app>/admin`, debug pages,
  `?preview_theme_id=`, draft/unpublished content URLs you saw in the sitemap).
- **FAIL:** content meant to be gated renders without the right role.

> Reminder: core `/admin` Shopify auth is **out of scope** (rule #3). This case is
> about *your* app/theme pages, not Shopify's admin login.

---

## Area 3 — Input validation (XSS & other injection)

Test every place user input is **stored or reflected**: search box, contact/forms,
product reviews, account fields (name, address), newsletter signup, any custom-app
input, and URL query params that echo into the page.

### 3.1 Reflected XSS
- **Inputs (try one at a time, observe where it lands in the response):**
  ```
  "><script>alert(1)</script>
  "><img src=x onerror=alert(1)>
  '"><svg onload=alert(1)>
  javascript:alert(1)
  {{7*7}}            ← also catches template injection (see 3.4)
  ```
- Put the marker in the **search query**, any reflected param, and error messages.
- **FAIL:** payload executes, or breaks out of the HTML/attribute context
  unescaped. **PASS:** rendered as inert text / properly encoded.
- **Capture:** the URL/param, the raw response showing the unescaped reflection,
  screenshot of the alert if it fires.

### 3.2 Stored XSS
- Submit the same payloads into anything persisted: **product reviews**, account
  name/address, custom-app form fields, order notes.
- Then view the page where that content is **displayed back** (your account, an
  admin/app view, another user's view of a review).
- **FAIL:** stored payload executes when the content is rendered. This is more
  severe than reflected — note who the victim is (other customers? a staff admin
  viewing reviews?).
- **Capture:** the submission request + the rendering page + screenshot.

### 3.3 HTML/markup injection & open-attribute breakout
- Where full `<script>` is stripped, test partial breakouts: unmatched quotes,
  `onmouseover=`, `style=`, `<a href=…>`, markdown/BBCode if the field supports it.
- **FAIL:** you can inject clickable/styled markup or event handlers.

### 3.4 Server-side template injection (SSTI)
- In custom-app fields especially, try `{{7*7}}`, `${7*7}`, `#{7*7}`,
  `<%= 7*7 %>`. If the response shows `49`, the input hits a template engine.
- **FAIL:** arithmetic is evaluated → escalate carefully, document, **do not** run
  destructive payloads.

### 3.5 Other injection (light, manual)
- **SQL/NoSQL:** in custom-app search/filter params, a single `'` or `")` that
  produces a 500 / DB error string is a signal. Note it; **do not** run `sqlmap`
  or data-extraction payloads (rule #2). One error-trigger char, then stop.
- **Header/redirect:** params like `?return_url=`, `?redirect=`, `?checkout_url=` —
  set to `https://evil.example` and see if you get an open redirect, or inject
  `\r\n` for header splitting.
- **FAIL:** DB error reflected, or open redirect off-domain.

---

## Area 4 — Cart & checkout logic (test mode only)

> Confirm test gateway first (`01-setup.md`). These are **business-logic** tests —
> you're attacking *your* cart/discount logic, not Shopify's payment rails.

### 4.1 Price tampering
- Intercept the add-to-cart / cart-update request in Burp. Look for a `price`,
  `amount`, or line-item total in the request or in any hidden form field /
  client-side JS that the server trusts.
- Change it (e.g. price → `0.01`) and submit; proceed toward checkout in test mode.
- **FAIL:** the server honours the client-supplied price. **PASS:** price is
  re-derived server-side from the product; your value is ignored.
- **Capture:** tampered request + the cart/checkout total that resulted.

### 4.2 Negative / overflow quantity
- Set quantity to `-1`, `0`, a huge number, or a decimal in the cart-update request.
- **FAIL:** negative quantity yields a **negative line total / credit**, or
  quantity logic breaks (free items, integer overflow, inventory bypass).
- **Capture:** request + resulting totals.

### 4.3 Discount / promo code abuse
- **Reuse:** apply a single-use or first-order-only code twice (same cart, then a
  second order). Does it stick the second time?
- **Stacking:** apply two codes, or the same code twice, and watch the total.
- **Logic:** apply a percentage code to a cart crafted so it rounds in your favour,
  or combine with the price/quantity tampering above.
- **Tampering:** modify the discount amount/percent in the request if it's
  client-supplied.
- **FAIL:** a code works beyond its intended limits, stacks when it shouldn't, or
  the discount value is attacker-controlled.
- **Capture:** the sequence of requests + before/after totals.

### 4.4 Currency / rounding / shipping edge cases
- Mixed-currency carts, a quantity/price combo that forces sub-cent rounding, or
  manipulating shipping-cost selection in the request.
- **FAIL:** totals can be driven below the legitimate amount.

> If any of the above only works because of a flaw in **Shopify's own checkout**
> (not your cart/theme/app logic) → rule #3: stop and report.

---

## Area 5 — Exposed data (secrets & security headers)

### 5.1 Secrets in source / JavaScript
- View source of key pages and read every custom `*.js` the theme/apps load.
- **Grep for:** `api_key`, `apikey`, `secret`, `token`, `password`, `Bearer `,
  `Authorization`, `AKIA` (AWS), `sk_live`/`pk_live` (Stripe), `shpat_`/`shpss_`
  (Shopify Admin/private-app tokens), Google Maps keys, Mailchimp/SendGrid keys,
  webhook signing secrets, `.myshopify.com` admin URLs with creds.
- Check: HTML comments, inline JS config objects (`window.__CONFIG__ = {…}`),
  source maps (`.js.map`), and any `/apps/<app>/…` JSON responses.
- **FAIL:** any live secret/credential recoverable from the client. A **leaked
  Shopify Admin API / private-app token is critical** (it can control the store).
- **Capture:** file/URL, line, the (redacted) secret, and what it unlocks.

### 5.2 Security headers
- `GET` the main pages and inspect response headers. Check for presence/quality of:
  - `Content-Security-Policy` (missing/`unsafe-inline` weakens your XSS defence)
  - `Strict-Transport-Security`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options` / CSP `frame-ancestors` (clickjacking)
  - `Referrer-Policy`, `Permissions-Policy`
  - Cookie flags on *your* cookies (`Secure`, `HttpOnly`, `SameSite`)
- **FAIL:** security-relevant headers missing on **pages/assets you serve**.
- **Note:** many headers are set by Shopify's edge and are **not yours to change**
  — flag those as informational / platform, don't log them as your defect.
- **Quick manual check (read-only, in scope, no load):**
  ```bash
  curl -sSI https://test.myshopapps.com/                # headers on home
  curl -sS  https://test.myshopapps.com/ | grep -Eio \
    'api[_-]?key|secret|token|bearer|shpat_[a-z0-9]+|sk_live_[a-z0-9]+|AKIA[0-9A-Z]{16}'
  ```

### 5.3 Information disclosure
- Error pages (trigger a 404/500 on your routes) — stack traces, framework/version
  banners, internal paths, debug output?
- Exposed files: `/robots.txt`, `/sitemap.xml`, source maps, `.git/`, backup files,
  `/apps/<app>/.env`-style leaks. (Request a handful by hand — **no wordlist
  fuzzing**, rule #2.)
- **FAIL:** internal detail, debug mode, or source/config exposed.

---

## Area 6 — Wrap-up checks

- Re-confirm every FAIL reproduces cleanly from a fresh session (no fluke/caching).
- For each finding, decide: is it **yours** (theme/content/custom app) or
  **Shopify's platform**? Platform issues → reported under rule #3, kept out of the
  "your defects" list.
- Fill `03-findings-register.md`, then promote confirmed items into
  `04-report-template.md` with severities from `05-severity-guide.md`.
