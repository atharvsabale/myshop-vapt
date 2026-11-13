# Security Assessment (VAPT) — test.myshopapps.com

> Final deliverable scaffold. Fill the bracketed parts from your findings register.
> Keep it tight: an exec summary a non-engineer can act on, then one section per
> confirmed finding with enough detail for a developer to fix and retest.

---

## 1. Executive summary

- **Target:** `https://test.myshopapps.com` (MyShopApps test Shopify store).
- **Scope:** store theme, content, and custom apps. Excluded: Shopify's own
  authentication and checkout platform, and all other hosts.
- **Engagement window:** [start] – [end]. **Tester:** [name].
- **Method:** manual VAPT (Burp Suite + browser), no automated scanning, no load.

**Headline:** [N] confirmed findings in your customisations — [c] Critical,
[h] High, [m] Medium, [l] Low. [One-line bottom line, e.g. "No critical issues;
the main risks are an IDOR on order history and a stored XSS in product reviews —
both fixable in the custom app / theme."]

| Severity | Count |
|----------|-------|
| Critical | |
| High | |
| Medium | |
| Low | |
| Info / platform (reported separately) | |

### Top risks (plain language)
1. [e.g. "A logged-in customer can view another customer's past orders by changing
   the order number in the URL."]
2. …
3. …

---

## 2. Scope & methodology

- Areas tested: authentication (login/signup/password-reset), access control
  (IDOR), input validation (XSS/injection), cart & checkout business logic,
  exposed data (secrets & security headers).
- Approach: manual, one test at a time, test-mode checkout only; see the playbook
  (`02-playbook.md`) for the exact test cases executed.
- Rules observed: single host only; no brute-force/flooding/scanners; Shopify's
  own auth & checkout left untouched (platform-looking issues reported, not probed).

### Coverage table

| Area | Tested | Result |
|------|:------:|--------|
| 1. Auth — weak passwords | ✅ | [summary] |
| 1. Auth — email enumeration | ✅ | |
| 1. Auth — reset link expiry/reuse | ✅ | |
| 2. Access control — orders IDOR | ✅ | |
| 2. Access control — account IDOR | ✅ | |
| 2. Access control — custom-app endpoints | ✅ | |
| 3. Input — reflected XSS | ✅ | |
| 3. Input — stored XSS | ✅ | |
| 3. Input — other injection (SQLi/SSTI/redirect) | ✅ | |
| 4. Cart — price tampering | ✅ | |
| 4. Cart — negative quantity | ✅ | |
| 4. Cart — discount reuse/abuse | ✅ | |
| 5. Exposed data — secrets in source/JS | ✅ | |
| 5. Exposed data — security headers | ✅ | |
| 5. Exposed data — info disclosure | ✅ | |

---

## 3. Findings

> One subsection per **confirmed** finding, ordered by severity. Pull from
> `03-findings-register.md`.

### 3.1 [F-00X] <Title> — <Severity>

- **Location:** [URL / endpoint / parameter]
- **Ownership:** Your theme/content/custom app
- **CVSS:** [vector + score, for High/Critical]
- **Description:** what the flaw is and why it exists.
- **Impact:** what an attacker achieves.
- **Steps to reproduce:**
  1.
  2.
- **Evidence:** [request/response excerpts, screenshot refs]
- **Remediation:** [specific fix]
- **Status:** Open / Fixed / Retested-closed

*(repeat per finding)*

---

## 4. Remediation summary (quick reference)

Standard fixes for the classes this engagement targets:

| Issue class | Fix |
|-------------|-----|
| Weak passwords | Enforce length (≥12) + complexity or breached-password check at signup & change |
| Email enumeration | Uniform responses + constant time on login, signup, and reset ("if an account exists, we've emailed you") |
| Reset-link flaws | Long random token, single-use, short TTL, invalidate on new request & on use, bind to account |
| IDOR | Server-side **authorization** on every object access — verify the session owns the order/account/record; never trust an id from the client |
| Reflected/stored XSS | Context-aware output encoding; sanitise on input *and* escape on output; a strict CSP as defence-in-depth |
| SSTI / injection | Never render user input through a template engine; parameterised queries in custom apps |
| Open redirect | Allow-list redirect targets to your own host |
| Price/quantity tampering | Recompute price server-side from the catalogue; reject non-positive quantities; never trust client totals |
| Discount abuse | Enforce usage limits & stacking rules server-side; validate code state per order |
| Secrets in client | Remove all keys/tokens from theme & JS; **rotate any leaked token immediately** (a leaked Admin API token = store compromise); move secrets server-side |
| Missing headers | Add CSP, HSTS, `X-Content-Type-Options`, frame-ancestors; set `Secure`/`HttpOnly`/`SameSite` on your cookies (where Shopify lets you control them) |

---

## 5. Items referred to Shopify / out of scope

Per the rules, anything that looked like a flaw in **Shopify's own platform**
(core auth, checkout rails, admin) was **not** further probed and is listed here
for the owner to raise with Shopify:

- [item + why it looks platform-owned, if any]

---

## 6. Appendix

- Test accounts used (labels only, no live passwords in the report).
- Timeline of testing (for log correlation).
- Tooling & versions (Burp build, browser).
- Evidence index (`evidence/F-00X/…`).
