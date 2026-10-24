# Remediation Guide

## Immediate Action: Upgrade PHP

Upgrading to a patched PHP release is the **only complete fix**.

| Branch | Upgrade To | Command (Debian/Ubuntu/Kali) |
|--------|-----------|------------------------------|
| 8.5.x | 8.5.12 | `apt-get update && apt-get install php8.5` |
| 8.4.x | 8.4.27 | `apt-get update && apt-get install php8.4` |
| 8.3.x | 8.3.36 | `apt-get update && apt-get install php8.3` |
| 8.2.x | 8.2.35 | `apt-get update && apt-get install php8.2` |
| 8.1 and older | Upgrade branch | No official patch available |

After upgrading, verify with:
```bash
php --version
php2shell-sentinel audit-local
```

---

## Temporary Mitigations (php.ini)

Apply while scheduling the upgrade. These are **partial** mitigations only.

```ini
; Removes the memory cap that CVE-2026-109618 abuses
; Enforce memory limits at the container/cgroup level instead
memory_limit = -1

; Disables session upload-progress path (CVE-2026-109618 attack vector)
session.upload_progress.enabled = 0

; Disables fatal-error backtrace path used by CVE-2026-109619 on PHP 8.5
fatal_error_backtraces = 0

; Reduces information disclosure
expose_php = Off
display_errors = Off
```

Apply in:
- `/etc/php/<version>/fpm/php.ini` (PHP-FPM)
- `/etc/php/<version>/apache2/php.ini` (mod_php)
- `/etc/php/<version>/cli/php.ini` (CLI)

Reload PHP-FPM after changes:
```bash
systemctl reload php8.4-fpm   # adjust version as needed
```

---

## Container / Cloud Deployments

For Docker-based deployments, rebuild with a patched base image:

```dockerfile
FROM php:8.4.27-apache
# or
FROM php:8.4.27-fpm
```

For cloud-managed PHP runtimes, check your vendor's advisory:
- **Palo Alto Networks** — [advisory](https://security.paloaltonetworks.com/CVE-2026-109618)
- **Google Cloud** — updated PHP base images available
- **AWS Elastic Beanstalk** — update platform version

---

## EOL PHP Versions (8.1 and older)

No official PHP patch will be released for PHP 8.1 or older.  
Options:

1. **Upgrade to PHP 8.2+** (recommended)
2. Use a **distribution-provided backport** if available (Debian LTS, RHEL, Ubuntu Advantage)
3. Apply php.ini mitigations above and add WAF rules to restrict upload-progress endpoints
4. Isolate the application from untrusted traffic
