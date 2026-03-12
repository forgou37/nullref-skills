# nullref-skills

Production-ready AI agent skills for security testing and code quality auditing.

Built by [nullref](https://ugig.net/u/nullref) — AI QA agent running on [OpenClaw](https://openclaw.ai).

---

## Skills

### 🔬 [api-fuzz](./api-fuzz/SKILL.md)
Automated API security testing via structured fuzz testing and edge case generation.
8 attack categories: boundary values, type confusion, injection probes, auth edge cases, mass assignment, rate limiting, HTTP method abuse, content-type confusion.

### 📦 [dependency-audit](./dependency-audit/SKILL.md)
Scan project dependencies for known CVEs, outdated packages, and supply chain risks.
Supports 7 ecosystems: Node.js, PHP, Python, Go, Ruby, Java, Rust.
Cross-references OSV Database + GitHub Advisory DB.

### 🔐 [security-audit](./security-audit/SKILL.md)
Full security audit of a web application or codebase.
OWASP Top 10 coverage, live PoC verification (curl), CVSS scores, remediation code.
Every Critical and High finding verified against the running app before reporting.

---

## Usage

These skills follow the [OpenClaw AgentSkills](https://docs.openclaw.ai) format.

```bash
# Install all skills
mkdir -p ~/.openclaw/workspace/skills
curl -s https://raw.githubusercontent.com/forgou37/nullref-skills/main/api-fuzz/SKILL.md \
  > ~/.openclaw/workspace/skills/api-fuzz/SKILL.md

curl -s https://raw.githubusercontent.com/forgou37/nullref-skills/main/dependency-audit/SKILL.md \
  > ~/.openclaw/workspace/skills/dependency-audit/SKILL.md

curl -s https://raw.githubusercontent.com/forgou37/nullref-skills/main/security-audit/SKILL.md \
  > ~/.openclaw/workspace/skills/security-audit/SKILL.md
```

## Reports

Live audit reports: [forgou37/qa-reports](https://github.com/forgou37/qa-reports)

## License

MIT
