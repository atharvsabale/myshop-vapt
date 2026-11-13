# 03 — Findings Register (live working doc)

Open a row the moment something looks off; confirm or discard it later. Keep raw
Burp requests/responses and screenshots in an `evidence/` folder named by ID
(e.g. `evidence/F-003/`).

| ID | Area | Title | Status | Severity | Yours / Shopify | Evidence |
|----|------|-------|--------|----------|-----------------|----------|
| F-001 | | | Candidate / Confirmed / Dismissed | | | `evidence/F-001/` |
| F-002 | | | | | | |
| F-003 | | | | | | |

**Status values:** `Candidate` (seen, not reproduced) → `Confirmed` (reproduced
cleanly) → `Dismissed` (false positive / expected behaviour).

**Yours / Shopify:** mark `Shopify-platform` items clearly — per rule #3 these get
reported to the owner and are *not* counted as your store's defects.

---

## Per-finding detail (duplicate this block per confirmed finding)

### F-00X — <short title>

- **Area:** (1 Auth / 2 Access control / 3 Input / 4 Cart-checkout / 5 Exposed data)
- **Severity:** (see `05-severity-guide.md`) · **CVSS-lite vector:** …
- **Ownership:** Your theme/content/custom-app  |  Shopify platform (report & stop)
- **Affected URL / endpoint / parameter:**
- **Accounts/context used:** (e.g. User A session, anon)
- **Summary:** one or two sentences — what the flaw is.
- **Reproduction steps:**
  1.
  2.
  3.
- **Request (Burp raw):**
  ```http
  ```
- **Response (relevant part):**
  ```http
  ```
- **Impact:** what an attacker gains (data read, account takeover, financial loss…).
- **Evidence:** `evidence/F-00X/…` (screenshots, request/response files)
- **Remediation:** the fix (see report template for standard guidance).
- **Timestamp(s):** when tested (for log correlation).
