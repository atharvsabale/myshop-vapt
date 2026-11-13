# 05 — Severity Guide (CVSS-lite)

Rate each confirmed finding consistently. Use this quick rubric; if you want a
formal score, run the vector through the CVSS 3.1 calculator and paste it in.

## Rating rubric

| Severity | Rule of thumb | Examples in this engagement |
|----------|---------------|-----------------------------|
| **Critical** | Full compromise / mass data exposure, little effort | Leaked Shopify Admin API token in JS; IDOR exposing *all* customers' orders; price-to-zero that completes a real order |
| **High** | Account takeover, cross-customer data, or clear financial loss | Stored XSS hitting staff/admin; IDOR reading another customer's orders/PII; reset-link reuse enabling takeover; discount reuse with real monetary impact |
| **Medium** | Meaningful but constrained; needs conditions or user interaction | Reflected XSS; email enumeration; weak password policy; open redirect; missing CSP that materially weakens defence |
| **Low** | Minor info leak / hardening gap, limited impact | Missing `X-Content-Type-Options`; verbose error without secrets; cookie missing `SameSite` |
| **Info** | Not exploitable on its own / platform-owned / best practice | Shopify-set headers you can't change; version banners; defence-in-depth notes |

## Scoring inputs to think about

- **Impact:** confidentiality (whose data?), integrity (can you change it?),
  availability (N/A here — no DoS testing), financial (checkout logic).
- **Exploitability:** auth required? which role? user interaction needed?
  network-reachable by any anonymous visitor?
- **Scope / blast radius:** one account vs all customers vs whole store.

## Ownership gate (apply before severity)

If the finding is in **Shopify's own platform** (checkout rails, core auth, admin):
- Mark **Ownership = Shopify platform**, severity **Info** in *your* register,
- and **report it separately** to the engagement owner per rule #3.
Only defects in **your theme / content / custom apps** get a real severity and go
in the headline findings count.

## CVSS vector slots (optional, for High/Critical)

```
CVSS:3.1/AV:N/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:N
```
Fill `?` per finding. `A:N` (no availability impact) is correct for this
engagement — you are not testing DoS.
