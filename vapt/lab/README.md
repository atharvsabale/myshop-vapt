# Local practice labs

**Deliberately-vulnerable** apps you run on your own machine to practice the
playbook test cases safely, offline, without touching `test.myshopapps.com`.

> Vulnerable by design. localhost-only. Do **not** deploy these anywhere.

| Lab | Area | Run |
|-----|------|-----|
| `login_lab.py` | 1 — Authentication | `python3 login_lab.py` → http://127.0.0.1:8000 |
| `idor_lab.py` | 2 — Access control (IDOR) | `python3 idor_lab.py` → http://127.0.0.1:8001 |
| `xss_lab.py` | 3 — Input validation (XSS/injection) | `python3 xss_lab.py` → http://127.0.0.1:8002 |
| `cart_lab.py` | 4 — Cart & checkout logic | `python3 cart_lab.py` → http://127.0.0.1:8003 |

---

# Login Lab — Area 1 (auth)

Login / signup / password-reset page.

## Run

```bash
python3 login_lab.py          # http://127.0.0.1:8000
python3 login_lab.py 8080     # custom port
```

No dependencies — Python 3 standard library only. Ctrl-C to stop (state is in-memory
and resets each run). Seeded accounts:

- `alice@example.com` / `Password123`
- `bob@example.com` / `hunter2`

## What to try (mapped to the playbook)

| Playbook case | How to see the flaw here |
|---------------|--------------------------|
| **1.1 Weak password policy** | Sign up with password `1` or `password` — it's accepted. |
| **1.2 User/email enumeration** | Login with a *known* email + wrong password → "Incorrect password"; login with an *unknown* email → "No account found". Signup and Forgot-password leak the same way. There's also a ~0.4s timing difference for real accounts (Burp Comparer). |
| **1.3 Reset link reuse / expiry / predictability** | Request a reset — the token is a small **sequential** number (`1001`, `1002`…), never expires, isn't invalidated when you request a new one, and **still works after use** (reuse it to reset again). |
| **5.2 Security headers** | Responses ship with no CSP / HSTS / `X-Content-Type-Options` — practice flagging missing headers with `curl -I`. |

The reset link is printed to the **server console** (and shown on the page) since
there's no real email.

## The point

Each flaw is labelled `# FLAW 1.x` in `login_lab.py`. Once you can spot and prove
them here, run the same techniques against the real store's auth surfaces per the
playbook — then write them up in `../03-findings-register.md`. The secure fix for
each is in the remediation table of `../04-report-template.md`.

---

# IDOR Lab — Area 2 (access control)

Customer account / orders app with **real session cookies**, so you prove each
flaw the correct way: log in as one user, keep *your* session, and reach *another*
user's object by changing an id.

## Run

```bash
python3 idor_lab.py          # http://127.0.0.1:8001
python3 idor_lab.py 8088     # custom port
```

Seeded accounts:

- `alice@example.com` / `alicepw` → customer **1001**, orders 5001 & 5003
- `bob@example.com` / `bobpw` → customer **1002**, orders 5002 & 5004

## What to try (mapped to the playbook)

| Playbook case | How to see the flaw |
|---------------|---------------------|
| **2.1 Orders IDOR** | Sign in as Alice, open `/orders/5002` (Bob's order) → you see his items, total & card last-4. Ids are sequential. |
| **2.2 Account/profile IDOR** | As Alice, visit `/account?id=1002` → view **and edit** Bob's profile (the id rides in a hidden field on save too). |
| **2.3 Custom-app endpoint, no auth** | Logged **out**, hit `/api/order?id=5001` → JSON order data with no session/HMAC at all. Walk the id. |
| **2.4 Forced browsing** | Visit `/apps/rewards/admin` → a custom-app "admin" page with no role check, dumping every customer. |

## The point

Each flaw is labelled `# FLAW 2.x` in `idor_lab.py`. The fix in every case is a
**server-side ownership/role check** on the object — never trust an id from the
client. Once you can spot and prove these locally, run the same id-swapping
technique against the real store's order/account/custom-app endpoints per the
playbook, then record findings in `../03-findings-register.md`.

---

# XSS Lab — Area 3 (input validation)

Five input surfaces, each with an intentional flaw, so you can see exactly where
output-encoding is missing.

## Run

```bash
python3 xss_lab.py          # http://127.0.0.1:8002
python3 xss_lab.py 8089     # custom port
```

## What to try (mapped to the playbook)

| Playbook case | How to see the flaw |
|---------------|---------------------|
| **3.1 Reflected XSS** | `/search?q=<script>alert(1)</script>` — the query is echoed into the page unescaped. |
| **3.2 Stored XSS** | Post a review with body `<img src=x onerror=alert(1)>` → it fires for everyone who later opens `/reviews`. |
| **3.3 Attribute / HTML injection** | `/greet?name=x onmouseover=alert(1) y` → value lands in an **unquoted** attribute, so no `<>` needed. |
| **3.4 Server-side template injection** | `/render?t={{7*7}}` → prints `49`, proving input reached a template engine. |
| **3.5 Open redirect** | `/go?next=https://example.com` → 302 off-site with no allow-list. |

> Safety: the SSTI demo only evaluates a whitelisted arithmetic grammar
> (`[0-9 +-*/()]`), so `{{7*7}}` shows `49` but no real code runs on your machine —
> `{{__import__("os")}}` is left as literal text.

## The point

Each flaw is labelled `# FLAW 3.x` in `xss_lab.py`. The fix is **context-aware
output encoding** (HTML-escape on output, quote attributes, never render user input
through a template engine) plus a strict CSP as defence-in-depth. Prove the
technique here, then try it against the real store's search/forms/reviews per the
playbook and log findings in `../03-findings-register.md`.

---

# Cart Lab — Area 4 (cart & checkout logic)

A shop + cart + test-mode checkout whose server **trusts client-supplied price,
quantity and discount values**, so you can tamper and watch the total break.

## Run

```bash
python3 cart_lab.py          # http://127.0.0.1:8003
python3 cart_lab.py 8090     # custom port
```

The add-to-cart request takes `product`, `qty` and (optionally) `price`:
```
/cart/add?product=mug&qty=2&price=0.01
```

## What to try (mapped to the playbook)

| Playbook case | How to see the flaw |
|---------------|---------------------|
| **4.1 Price tampering** | Add `mug` (real £10) with `price=0.01` → charged £0.01. |
| **4.2 Negative quantity** | Add with `qty=-3` → negative line total / credit. |
| **4.3 Discount reuse/stack** | Apply `SAVE10` three times → stacks, no "one per order" rule. |
| **4.4 Totals / checkout** | `/checkout` carries the tampered total through (test mode, no real card). |

Full hands-on method with Burp: **`AREA4-manual-walkthrough.md`**.

## The point

Each flaw is labelled `# FLAW 4.x` in `cart_lab.py`. The fix is always the same:
recompute price/quantity/discounts **server-side** from trusted data; never trust a
value the client sent. Prove it here, then apply the same request-tampering method
to the real store per the walkthrough and log findings in `../03-findings-register.md`.

---

# Mobile / browser versions (open on a phone)

Self-contained HTML versions that run with no server — open them on a phone:

| File | Area |
|------|------|
| `login-lab-mobile.html` | 1 — Authentication |
| `idor-lab-mobile.html` | 2 — Access control (IDOR) |
| `cart-lab-mobile.html` | 4 — Cart & checkout |

The Python labs stay the better target for Burp work (real HTTP requests to
intercept); the mobile versions are for understanding and demoing the flaws anywhere.
