---
name: security-audit
description: >
  Perform a professional security and QA audit of a web application or codebase.
  Use when asked to audit, review, or security-test a GitHub repo, live URL, or source files.
  Produces an enterprise-grade report with CVSS scores, live PoC verification (curl tests against
  production), root cause with exact file and line, and remediation code.
  Covers OWASP Top 10, hardcoded secrets, broken access control, missing auth, input validation.
  Unique: every Critical and High finding is verified live against the running app before reporting.
---

# Security Audit

## Workflow

### Phase 1: Reconnaissance
1. Clone or read the repository; identify stack (language, framework, deployment)
2. Map the attack surface: all HTTP endpoints, API routes, public URLs
3. Identify entry points: user input, file upload, auth flows, API keys in code
4. Note dependencies: `package.json`, `requirements.txt`, `go.mod`, etc.

### Phase 2: Static Analysis
Read source files systematically. For each file, apply:
- See `references/owasp-patterns.md` for OWASP Top 10 patterns per language
- Flag secrets with regex patterns in `references/owasp-patterns.md`
- Check auth middleware presence on every route
- Note missing security headers, rate limiting, input validation

### Phase 3: Live Verification (critical differentiator)
For every Critical and High finding — **verify against the running app**.

**Strict rules (one violation = reputation gone):**
- Only `GET` and `HEAD` requests. Never `POST`, `PUT`, `PATCH`, `DELETE`
- Timeout: `--max-time 10` on every curl request
- Log every request before sending: `[PoC] GET https://target.app/api/endpoint`
- Never send payloads that write, modify, or delete data
- If in doubt about safety — mark as Static (code only), do not test live

```bash
# Example: verify unauthenticated endpoint
curl -s --max-time 10 https://target.app/api/endpoint
# Log before running: [PoC] GET https://target.app/api/endpoint
```
- Document: HTTP method, URL, response status, response snippet (max 200 chars)

### Phase 4: Structured Output
Before writing the report, output findings as JSON (for auto-processing):
```json
{
  "target": "repo-name",
  "date": "YYYY-MM-DD",
  "findings": [
    {
      "id": "C-01",
      "title": "Finding title",
      "severity": "Critical",
      "cvss": 9.1,
      "status": "Confirmed",
      "location": "path/to/file.ts:42",
      "owasp": "A01"
    }
  ],
  "summary": { "critical": 1, "high": 2, "medium": 3, "low": 1 }
}
```
Then render full human report. See `references/report-format.md` for template.

Quick structure:
1. Executive Summary (3–5 sentences, non-technical)
2. Finding Distribution table
3. Findings: Critical → High → Medium → Low
4. Positive Observations
5. Remediation Priority Table

Each finding must include:
- Severity + CVSS score (see `references/severity-model.md`)
- File path + line number
- Live PoC output (for Critical/High)
- Root cause explanation
- Remediation code snippet

## Rules
- English only for all reports
- No speculative findings — evidence required for every issue
- Live testing: GET/HEAD only, `--max-time 10`, log every request, never modify data
- CVSS scores required for Critical and High
- Remediation must include working code, not just description
- Mark every finding as: Confirmed (live-tested) or Static (code only)
- This skill is v1 — update after each real audit based on what actually worked
