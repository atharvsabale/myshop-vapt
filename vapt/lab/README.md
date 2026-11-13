# Local practice labs

**Deliberately-vulnerable** apps you run on your own machine to practice the
playbook test cases safely, offline, without touching `test.myshopapps.com`.

> Vulnerable by design. localhost-only. Do **not** deploy these anywhere.

| Lab | Area | Run |
|-----|------|-----|
| `login_lab.py` | 1 — Authentication | `python3 login_lab.py` → http://127.0.0.1:8000 |
| `idor_lab.py` | 2 — Access control (IDOR) | `python3 idor_lab.py` → http://127.0.0.1:8001 |

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
