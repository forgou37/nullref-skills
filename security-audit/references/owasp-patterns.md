# OWASP Top 10 — Detection Patterns

## A01: Injection

| Stack | Vulnerable Pattern | Flag When |
|-------|-------------------|-----------|
| JS/TS | `db.query("..." + userInput)` | String concat in SQL |
| JS/TS | `` eval(`${userInput}`) `` | Dynamic eval with user data |
| Python | `cursor.execute("..." % user_id)` | String format in SQL |
| Python | `os.system(f"cmd {input}")` | Shell command with input |
| Next.js API | `prisma.$queryRaw(\`...\`)` | Raw query without parameterization |

Also check: LDAP injection, NoSQL (`$where`, `$regex`), path traversal (`../`), template injection.

## A02: Broken Authentication

- Passwords stored as plaintext or MD5/SHA1 without salt
- No rate limiting on `/login`, `/register`, `/reset-password`
- JWT with `alg: "none"` accepted or weak HS256 secret
- Missing `exp` claim in JWT
- Session ID not rotated after login
- Credentials over HTTP

## A03: Sensitive Data Exposure — Secret Detection Regex

```
# AWS Access Key
AKIA[0-9A-Z]{16}

# GitHub Token
gh[ps]_[A-Za-z0-9_]{36,}

# Generic API Key / Secret
(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}["']?

# Private Key
-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----

# DB Connection String with password
(?i)(mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@

# Stripe
sk_live_[0-9a-zA-Z]{24,}

# Supabase Service Key (starts with eyJ, long)
eyJ[A-Za-z0-9_\-]{100,}
```

Files to check immediately: `.env*`, `*.pem`, `*.key`, `docker-compose.yml`, CI/CD configs.

## A04: Broken Access Control

- Routes without auth middleware
- No ownership check (user A accessing user B's resource via predictable ID)
- `CORS: *` on authenticated endpoints
- Admin endpoints without role check
- Missing `X-Frame-Options` or CSP `frame-ancestors`
- File upload without type/size validation

## A05: Security Misconfiguration

- `DEBUG=True` or `NODE_ENV=development` in production
- Stack traces in API error responses
- Default CORS `*` on sensitive endpoints
- Missing security headers: `HSTS`, `CSP`, `X-Content-Type-Options`, `X-Frame-Options`

Check Next.js `next.config.js` for `headers()` configuration.

## A06: XSS

- React: `dangerouslySetInnerHTML` with user data
- `innerHTML =` with user data
- EJS/Handlebars: `<%- %>` or `{{{ }}}` (unescaped output)

## A07: Using Vulnerable Components

Check `package.json` for known-vulnerable packages. Flag for `npm audit`.
Check `requirements.txt` for unpinned versions.

## A08: Insufficient Logging

- Auth events not logged (login, failed attempts, logout)
- Silent catch blocks: `catch(e) {}`
- Sensitive data in logs: `console.log(password)`
- No request correlation IDs

## JavaScript / TypeScript Checklist

- [ ] No `eval()` or `Function()` with user input
- [ ] No `innerHTML`/`dangerouslySetInnerHTML` with unescaped data
- [ ] Parameterized queries for all DB operations
- [ ] `helmet` or security headers middleware
- [ ] Input validation (Zod, Joi, Yup)
- [ ] `httpOnly`, `secure`, `sameSite` on cookies
- [ ] CSRF tokens on state-changing endpoints

## Python Checklist

- [ ] No `eval()`, `exec()`, `os.system()` with user input
- [ ] Parameterized queries (not f-strings in SQL)
- [ ] `yaml.safe_load()` not `yaml.load()`
- [ ] No `pickle.loads()` on untrusted data
