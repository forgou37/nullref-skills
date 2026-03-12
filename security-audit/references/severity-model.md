# Severity Model

## Critical (CVSS 9.0–10.0)
- Remote compromise, RCE, or full data breach possible without authentication
- Unauthenticated access to sensitive data at scale
- Fix immediately before next deployment

**Example:** Unauthenticated endpoint exposes all user data, no auth required.

## High (CVSS 7.0–8.9)
- Exploitable with moderate effort
- Auth bypass, significant data exposure, or strong abuse vector
- Fix in current sprint

**Example:** API key or secret stored in source code and committed to git.

## Medium (CVSS 4.0–6.9)
- Requires specific preconditions
- Limited impact alone, dangerous if combined with other issues
- Fix with clear owner and deadline

**Example:** Missing rate limiting on login endpoint (enables brute force).

## Low (CVSS 0.1–3.9)
- Defense-in-depth gap only
- Low exploitability, minimal impact
- Backlog, reassess during hardening

**Example:** Missing `X-Content-Type-Options` header.

## Confidence Levels
- **Confirmed** — live-tested against running app, response captured
- **Static** — found in source code, not live-verified (note this in finding)

Never report Confirmed if not live-tested.

## CVSS Quick Scoring (simplified)

| Factor | Weight |
|--------|--------|
| No auth required to exploit | +3.0 |
| Exposed in production (not just dev) | +2.0 |
| Sensitive data exposed (PII, tokens, passwords) | +2.0 |
| Requires auth to exploit | -2.0 |
| Limited data exposed | -1.0 |
| Requires insider/admin access | -2.0 |

Start at 5.0 (Medium baseline), apply adjustments, cap at 10.0.
