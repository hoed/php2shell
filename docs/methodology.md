# Assessment Methodology

## 1. Vulnerability Background

### CVE-2026-109618 — OOM Interrupt Use-After-Free

When PHP reaches its `memory_limit` mid-request, the OOM handler interrupts
execution while internal request structures are only partially initialised.
The cleanup routine then processes that broken state as valid data, enabling
an attacker who can trigger OOM conditions to achieve remote code execution
and memory disclosure (e.g. session tokens, API keys, TLS private keys from
adjacent requests).

**Attack surface:** Any PHP server with a numeric `memory_limit`.  
**Affected versions:** PHP 5.4.0 through 8.5.11.

### CVE-2026-109619 — Stale Global State Use-After-Free

PHP-FPM and Apache mod_php reuse worker processes across requests. When a
fatal error occurs, request-specific global state can survive in freed memory.
A subsequent request on the same worker may access that state before normal
initialisation resets it, allowing arbitrary code execution.

**Attack surface:** PHP-FPM (all pool configurations), Apache mod_php.  
**Affected versions:** PHP 5.4.0 through 8.5.11.

---

## 2. Detection Approach

This toolkit uses **passive, non-destructive detection only**:

| Check | Method | Risk |
|-------|--------|------|
| Local binary version | `php --version` | None |
| php.ini risk settings | File read (no modification) | None |
| PHP-FPM pool config | File read (no modification) | None |
| Remote HTTP headers | Single HEAD/GET request | Minimal |

We compare the detected PHP version against the official patch matrix and
report status as VULNERABLE, PATCHED, UNSUPPORTED_EOL, or UNKNOWN.

We do **not** send:
- Memory-allocation stress requests
- Crafted multipart uploads
- Session upload-progress triggers
- Any form of exploit payload

---

## 3. Confidence Levels

| Level | Meaning |
|-------|---------|
| HIGH | Version obtained directly from binary or unambiguous header |
| MEDIUM | Version inferred from HTTP header (may be modified by server config) |
| LOW | Version absent or ambiguous; status inconclusive |

A MEDIUM remote confidence means the server *reports* a vulnerable version but
could have the banner spoofed or patched by a distribution without updating
the version string. Always confirm with a local audit when possible.

---

## 4. Scope and Authorisation

Remote assessment requires an explicit `--allowlist`. The toolkit will **not**
request targets outside the allowlist. Responsibility for obtaining written
authorisation before running assessments rests with the operator.

---

## 5. Remediation Priority

1. **Upgrade PHP** — the only complete fix (patched releases: 8.5.12, 8.4.27, 8.3.36, 8.2.35)
2. **Apply php.ini mitigations** while scheduling the upgrade
3. **Isolate PHP workers** — use `pm=ondemand` or container-per-request where feasible
4. **Monitor logs** for OOM events and unexpected fatal errors
5. **Update EOL installs** — PHP 8.1 and older will not receive an official patch
