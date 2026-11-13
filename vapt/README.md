# VAPT — test.myshopapps.com

Execution-ready vulnerability assessment & penetration-testing pack for the
MyShopApps **test** Shopify store. Built from the engagement brief in
`VAPT_task.docx`.

This is a **manual, hands-on** engagement. Nothing here runs itself — you drive
it in Burp Suite + a browser, one test at a time, and record results as you go.

## Files

| File | Purpose |
|------|---------|
| [`00-rules-of-engagement.md`](00-rules-of-engagement.md) | Scope, hard rules, what is in/out of bounds, stop conditions |
| [`01-setup.md`](01-setup.md) | Burp + browser setup, test accounts, test-mode payment cards |
| [`02-playbook.md`](02-playbook.md) | The actual test cases — steps, payloads, pass/fail, for all 6 areas |
| [`03-findings-register.md`](03-findings-register.md) | Live table you fill in as you find things |
| [`04-report-template.md`](04-report-template.md) | Final deliverable scaffold (exec summary → findings → remediation) |
| [`05-severity-guide.md`](05-severity-guide.md) | How to rate each finding consistently (CVSS-lite) |

## How to use it

1. Read `00-rules-of-engagement.md` **first**. The brief has hard limits — the
   most important being: **do not test Shopify's own login/checkout**, only your
   theme, content, and custom apps. If a bug looks like Shopify's platform, stop
   and report it.
2. Do `01-setup.md` (create your test cred, wire up Burp).
3. Work through `02-playbook.md` top to bottom, one test case at a time. Go slow
   — no automated scanners, no brute force, no flooding.
4. Every time something looks off, open a row in `03-findings-register.md`.
5. At the end, lift confirmed findings into `04-report-template.md`.

## Scope at a glance

- **Target:** `https://test.myshopapps.com` (test Shopify store, admin GUI) — **only** this host.
- **Test areas:** auth (login/signup/reset), access control (IDOR), input validation (XSS/injection), cart & checkout logic, exposed data (secrets/headers).
- **Out of scope:** Shopify platform auth & checkout internals, any other host, anything destructive, DoS/brute-force/flooding.
