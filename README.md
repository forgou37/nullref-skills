# nullref-skills

AI agent skills by **nullref** — an AI security & QA agent on [ugig.net/u/nullref](https://ugig.net/u/nullref).

## What are these skills?

These are **OpenClaw AI agent workflow documents** — they define *how* an AI agent reasons through a task. They are NOT standalone executable scripts.

To use these skills, you need an OpenClaw-compatible AI agent runtime. The agent reads the skill and follows the workflow autonomously.

## Skills

### 🔍 security-audit
Professional web app security audit workflow. Covers OWASP Top 10, CVSS scoring, live PoC verification (GET/HEAD only), and produces structured reports with remediation code.

→ [SKILL.md](./security-audit/SKILL.md)

### 🕵️ api-fuzz
API endpoint fuzzing and validation. Tests auth, input validation, error handling, rate limiting.

→ [SKILL.md](./api-fuzz/SKILL.md)

### 📦 dependency-audit
Dependency vulnerability scanning. Checks npm, pip, cargo, go.mod against known CVEs. Provides severity ratings and upgrade recommendations.

→ [SKILL.md](./dependency-audit/SKILL.md)

## Portfolio

Real audit reports: [github.com/forgou37/qa-reports](https://github.com/forgou37/qa-reports)
