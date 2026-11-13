# 00 — Rules of Engagement

These come straight from the engagement brief. Treat them as hard limits.

## Scope

- **In scope:** `https://test.myshopapps.com` only — specifically **the parts you
  control**: your theme, your content, and your custom apps.
- **Out of scope:** every other host. No pivoting to `*.myshopify.com` internals,
  payment processors, CDNs, or any third-party domain you see in traffic.

## Hard rules

1. **Only `test.myshopapps.com`.** Nothing else. If a redirect or asset sends you
   to another domain, do not test that domain.
2. **No brute-force, no flooding, no load.** Manual only. No automated scanners
   (no Burp Active Scan, no `sqlmap`, no `ffuf`/`dirb` wordlist runs against the
   live site, no credential stuffing). Go slow, test one thing at a time.
3. **Do NOT attack Shopify's own login or checkout system.** You are testing
   *your* customisations, not Shopify's platform. If a bug looks like it lives in
   Shopify's own auth or checkout flow → **stop, document it, and report it to the
   engagement owner.** Do not keep probing it.
4. **Checkout: test mode only.** Use Shopify Bogus Gateway / test cards. Never a
   real card. Never place a real paid order.
5. **Data hygiene.** Do not exfiltrate, modify, or delete real customer data. If
   an access-control test *would* expose another customer's real data, prove the
   vuln with the minimum evidence (one record, redacted) and stop — do not harvest.

## Stop-and-report conditions

Stop testing and notify the engagement owner immediately if you hit any of:

- A bug that appears to be in **Shopify's own platform** (checkout, payments,
  core auth, admin), not your customisation.
- Any sign you can reach **another real customer's** personal/payment data.
- Anything that looks like it could affect **production** rather than this test store.
- Accidental data modification/deletion, or the site degrading/erroring under your
  manual testing.

## Evidence standard

For every finding, capture: the request (Burp raw), the response, a screenshot,
the exact reproduction steps, and the account/context used. Redact real PII in
anything you save. Timestamp each test (helps correlate with their server logs).

## Working posture

- One browser profile per identity (see `01-setup.md`). Never mix cookies.
- Throttle manually. A human clicking pace is the target rate.
- Log every URL you touch — a simple sequential record makes the final report and
  any "what did you do at 14:32?" question trivial to answer.
