# Login Lab — local practice target (Area 1)

A **deliberately-vulnerable** login / signup / password-reset page you run on your
own machine. Use it to practice the authentication test cases in `../02-playbook.md`
safely, offline, without touching `test.myshopapps.com`.

> Vulnerable by design. localhost-only. Do **not** deploy it anywhere.

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
