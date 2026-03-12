---
name: dependency-audit
version: 1.2.0
description: >
  Scan project dependencies for known CVEs, outdated packages, and supply chain risks.
  Use when asked to audit dependencies, check for vulnerable packages, or review supply chain
  security. Supports Node.js, PHP, Python, Go, Ruby, and Java. Cross-references OSV Database
  and GitHub Advisory Database with batch queries. Produces a prioritized report with CVE IDs,
  CVSS scores, fixed versions, and upgrade paths. Also flags abandoned packages and license risks.
homepage: https://github.com/forgou37/qa-reports
metadata:
  {
    "nullref": {
      "emoji": "📦",
      "category": "security",
      "requires": { "bins": ["curl", "git"] },
      "author": "nullref (https://ugig.net/u/nullref)",
      "report_format": "markdown",
      "output_dir": "qa-reports"
    }
  }
---

# Dependency Audit

Scan project dependencies for known CVEs, outdated packages, and supply chain risks. Covers 6 ecosystems. Every vulnerability is cross-referenced against OSV and GitHub Advisory databases before reporting.

## When to Use

✅ **USE this skill when:**
- Auditing a project's third-party dependencies for known vulnerabilities
- Checking whether a package is abandoned or dangerously outdated
- Producing a software bill of materials (SBOM) for a codebase
- Pre-release security checks or compliance reviews
- A maintainer hasn't updated deps in months and you want to know the blast radius

## When NOT to Use

❌ **DON'T use this skill when:**
- You need to find zero-days in dependencies (no CVE = out of scope here)
- You want to audit the application's own code (use `security-audit` skill instead)
- The project uses private package registries without internet-accessible metadata
- You need runtime analysis (this is static manifest analysis only)

## Setup

**Requirements:** `curl`, `git`

**Optional tools that improve results:**
```bash
# Node.js — native audit (more complete than OSV for npm)
npm audit --json

# PHP — native audit
composer audit --format=json

# Python — safety check
pip install safety && safety check --json

# Go — govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
```

This skill works **without** any of the above — it falls back to OSV API queries. Native tools are used when available and add signal, not replace the workflow.

---

## Workflow

### Phase 1: Ecosystem Detection

Scan repo root and subdirectories for manifest files:

| File | Ecosystem | Package Registry |
|------|-----------|-----------------|
| `package.json` | Node.js | npm |
| `composer.json` | PHP | Packagist |
| `requirements.txt`, `pyproject.toml`, `Pipfile.lock` | Python | PyPI |
| `go.mod` | Go | Go Proxy |
| `Gemfile.lock` | Ruby | RubyGems |
| `pom.xml`, `build.gradle` | Java | Maven Central |
| `Cargo.toml` | Rust | crates.io |

```bash
find . -maxdepth 3 \( \
  -name "package.json" -o -name "composer.json" -o \
  -name "requirements.txt" -o -name "go.mod" -o \
  -name "Gemfile.lock" -o -name "pom.xml" -o -name "Cargo.toml" \
\) -not -path "*/node_modules/*" -not -path "*/vendor/*"
```

### Phase 2: Extract Dependencies

Parse manifests to get `name@version` pairs.

**Node.js:**
```bash
cat package.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
deps = {**d.get('dependencies',{}), **d.get('devDependencies',{})}
for k,v in deps.items(): print(f'{k}@{v.lstrip(\"^~>=<\")}')
"
```

**PHP:**
```bash
cat composer.lock | python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d.get('packages',[]): print(f\"{p['name']}@{p['version']}\")
"
```

**Python:**
```bash
# requirements.txt
grep -v '^#' requirements.txt | grep '==' | sed 's/==/@/'

# pyproject.toml
cat pyproject.toml | grep -A100 '\[tool.poetry.dependencies\]' | grep '='
```

**Go:**
```bash
grep -v '^module\|^go ' go.mod | grep '^\t' | awk '{print $1"@"$2}'
```

### Phase 3: Vulnerability Lookup

Use OSV batch API — most efficient, one request per ecosystem:

```bash
# Build batch query (Node.js example)
python3 -c "
import json
packages = [
  {'name': 'lodash', 'version': '4.17.15'},
  {'name': 'express', 'version': '4.17.1'}
]
queries = [{'package': {'name': p['name'], 'ecosystem': 'npm'}, 'version': p['version']} for p in packages]
print(json.dumps({'queries': queries}))
" | curl -s --max-time 30 \
  -X POST https://api.osv.dev/v1/querybatch \
  -H "Content-Type: application/json" \
  -d @-
```

OSV ecosystem names:
| Manifest | OSV ecosystem |
|----------|--------------|
| npm | `npm` |
| Packagist | `Packagist` |
| PyPI | `PyPI` |
| Go | `Go` |
| RubyGems | `RubyGems` |
| Maven | `Maven` |
| crates.io | `crates.io` |

**Fallback — GitHub Advisory Database:**
```bash
curl -s --max-time 10 \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/advisories?affects=lodash&ecosystem=npm&per_page=5"
```

**Native tools (run if available, override OSV results):**
```bash
# npm
npm audit --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
for name, vuln in d.get('vulnerabilities', {}).items():
    print(name, vuln.get('severity'), vuln.get('fixAvailable'))
"

# composer
composer audit --format=json 2>/dev/null

# Python safety
safety check --json 2>/dev/null
```

### Phase 4: Outdated Package Detection

Beyond CVEs, flag packages that are significantly stale:

```bash
# npm latest
curl -s --max-time 10 "https://registry.npmjs.org/lodash/latest" | python3 -c "
import json,sys; d=json.load(sys.stdin); print(d.get('version'))
"

# PyPI latest
curl -s --max-time 10 "https://pypi.org/pypi/requests/json" | python3 -c "
import json,sys; d=json.load(sys.stdin); print(d['info']['version'])
"

# Packagist latest
curl -s --max-time 10 "https://repo.packagist.org/p2/laravel/framework.json" | python3 -c "
import json,sys; d=json.load(sys.stdin)
pkgs = d['packages'].get('laravel/framework', [])
if pkgs: print(pkgs[0]['version'])
"
```

Flag as **Outdated** if:
- More than **2 major versions** behind latest
- Last release > **2 years** ago (check `time` field in npm registry)
- Explicitly **deprecated** or **abandoned** (check registry metadata)

### Phase 5: License Risk Check

Flag licenses that may create legal obligations:

```bash
# npm: read license field
cat package.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
for k,v in d.get('dependencies',{}).items():
    # Check license from installed node_modules if available
    import os
    pkg_json = f'node_modules/{k}/package.json'
    if os.path.exists(pkg_json):
        with open(pkg_json) as f:
            pkg = json.load(f)
            print(k, pkg.get('license','UNKNOWN'))
"
```

License risk tiers:
| Risk | Licenses | Issue |
|------|----------|-------|
| 🔴 High | AGPL-3.0, SSPL | Must open-source your app if distributed |
| 🟡 Medium | GPL-2.0, GPL-3.0 | Copyleft — triggers on distribution |
| 🟢 Low | MIT, Apache-2.0, BSD | Permissive — attribution only |
| ⚪ Unknown | `UNLICENSED`, missing | No license = all rights reserved by author |

### Phase 6: Risk Scoring

For each finding, assign severity:

| CVSS Score | Severity |
|-----------|---------|
| 9.0 – 10.0 | 🔴 Critical |
| 7.0 – 8.9 | 🟠 High |
| 4.0 – 6.9 | 🟡 Medium |
| 0.1 – 3.9 | 🔵 Low |

**Transitive dependencies:** report only Critical/High (direct deps: report all).

**Prioritization matrix:**
```
Direct + Critical + has_fix     → Fix immediately
Direct + High + has_fix         → Fix this sprint
Transitive + Critical           → Investigate + plan upgrade
Direct + no_fix                 → Monitor + evaluate alternatives
Outdated + no_vuln              → Schedule upgrade
```

### Phase 7: Structured Output

JSON summary before the full report:

```json
{
  "target": "repo-name",
  "date": "YYYY-MM-DD",
  "commit": "abc1234",
  "ecosystems": ["npm", "Packagist"],
  "total_packages": {
    "direct": 42,
    "dev": 18,
    "transitive": 0
  },
  "findings": [
    {
      "id": "CVE-2021-23337",
      "package": "lodash",
      "installed_version": "4.17.15",
      "fixed_version": "4.17.21",
      "severity": "High",
      "cvss": 7.2,
      "title": "Command Injection via template",
      "direct": true,
      "ecosystem": "npm",
      "osv_id": "GHSA-35jh-r3h4-6jhm",
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]
    }
  ],
  "outdated": [
    {
      "package": "moment",
      "installed": "2.24.0",
      "latest": "2.30.1",
      "major_lag": 0,
      "last_release_days": 890,
      "status": "maintenance-mode"
    }
  ],
  "license_issues": [],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "outdated": 4,
    "license_issues": 0
  }
}
```

### Phase 8: Report

Save full English report to `qa-reports/<target>-deps.md`.

Report structure:
1. **Executive Summary** — total packages, vulnerability count, risk level
2. **Scope** — ecosystems, manifest files analyzed, tool versions
3. **Finding Distribution** table
4. **Vulnerable Packages** — Critical → High → Medium → Low (with CVE ID, CVSS, fix)
5. **Outdated Packages** — table with installed / latest / lag
6. **License Issues** — if any
7. **Positive Observations**
8. **Remediation Commands** — ready-to-run upgrade commands per ecosystem

Example remediation section:
```bash
# Fix Critical/High vulnerabilities
npm update lodash@4.17.21
npm update minimist@1.2.6

# Upgrade outdated packages
npm update moment@2.30.1

# Or use npm audit fix for bulk remediation
npm audit fix --force
```

Commit report:
```bash
cd /path/to/workspace
git add qa-reports/<target>-deps.md
git commit -m "audit: <target> dependency scan"
```

---

## Rules

- **English only** for all reports
- **CVE ID required** for every vulnerability finding (skip if genuinely no CVE assigned)
- **Fixed version required** — if no fix exists, say "No fix available — consider alternative"
- **Transitive vulnerabilities**: report Critical and High only
- **Do not install or run package managers** — read manifests and lockfiles directly
- `"No known CVEs"` ≠ `"safe"` — always note if OSV returned no results
- **CVSS score required** for all Critical and High findings
- All curl calls: `--max-time 30` for OSV batch, `--max-time 10` for single lookups

---

## Changelog

- **1.2.0** — Added license risk check, Rust/Java support, prioritization matrix, remediation commands
- **1.1.0** — Added outdated package detection, GitHub Advisory fallback, native tool integration
- **1.0.0** — Initial release (OSV batch query, 5 ecosystems)
