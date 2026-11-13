# 01 — Setup

## Accounts (create your own test creds)

The brief says: *create your test login cred*. You need **at least two** customer
identities to test access control (IDOR) — you prove the bug by logging in as
User A and trying to reach User B's data.

| Label | Email | Password | Customer ID | Notes |
|-------|-------|----------|-------------|-------|
| User A (attacker) | `vapt-a+<you>@example.com` | (strong, unique) | _fill after signup_ | Place 1–2 test orders so there's an order ID to reference |
| User B (victim) | `vapt-b+<you>@example.com` | (strong, unique) | _fill after signup_ | Place a test order; this is the data A must NOT reach |

> Use `+tag` addressing or a catch-all you control so both land in an inbox you
> can read (needed for password-reset-link testing). Do **not** use a real
> customer's address.

Record the numeric **customer ID** and **order IDs/tokens** for each — you'll be
tampering with these in area 2 (access control).

## Tooling

- **Browser:** a clean profile (or two — one per identity) with no extensions that
  rewrite traffic. Firefox or Chrome both fine.
- **Burp Suite** (Community is enough for manual work):
  - Proxy → Intercept, with the browser proxied through Burp (use Burp's embedded
    browser to skip cert hassle, or install the Burp CA in your browser).
  - **Target → Scope:** add `test.myshopapps.com` and turn on "show only in-scope".
    This keeps you honest about rule #1 and keeps your sitemap clean.
  - Tools you WILL use: Proxy (observe), **Repeater** (hand-modify one request at a
    time), Decoder, Comparer.
  - Tools you will **NOT** use: Active Scanner, Intruder in any high-volume mode.
    Intruder is acceptable *only* for a tiny, hand-picked payload list sent slowly
    (e.g. 5 XSS strings into one field) — never as a fuzzer/wordlist runner.
- **Note-taking:** keep `03-findings-register.md` open. One row per candidate issue.

## Checkout test mode

Before any cart/checkout testing, confirm the store is on a test gateway:

- Shopify **Bogus Gateway** or Payments **test mode** enabled.
- Test card numbers (Bogus Gateway): `1` = success, `2` = failure, `3` = exception.
  Any future expiry, any CVV. (If real Shopify Payments test mode is on instead,
  use its documented `4242…` test PAN.)
- If you cannot confirm test mode is on → **stop** and ask the owner before touching
  checkout.

## Baseline capture (do this before you change anything)

Walk the store once as a normal user with Burp recording passively, to build a
sitemap of **your** surfaces:

- Home, collections, product pages, search, cart, account area, login/signup/reset
  pages, any custom-app pages/sections your theme adds, any `/apps/*` proxy routes.
- Note which pages are yours (theme/liquid/custom app) vs. Shopify-native. Your
  testing concentrates on the former.
