"""Local PHP installation auditor.

Inspects PHP binaries, php.ini, and PHP-FPM pools found on the local system.
Never modifies any configuration file.
"""

from __future__ import annotations

import configparser
import glob
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .models import (
    AssessmentReport,
    VulnerabilityFinding,
    VulnStatus,
    RemoteStatus,
)
from .version_parser import assess_version, parse_php_version

logger = logging.getLogger(__name__)

# Common PHP binary locations on Debian/Kali
_PHP_BINARY_PATTERNS = [
    "php",
    "php8",
    "php7",
    "php5",
    "/usr/bin/php*",
    "/usr/local/bin/php*",
    "/usr/sbin/php-fpm*",
    "/usr/sbin/php*-fpm",
]

# php.ini search paths
_INI_PATTERNS = [
    "/etc/php*/*/php.ini",
    "/etc/php*/php.ini",
    "/usr/local/etc/php.ini",
    "/usr/local/lib/php.ini",
]

# PHP-FPM pool config patterns
_FPM_POOL_PATTERNS = [
    "/etc/php*/fpm/pool.d/*.conf",
    "/usr/local/etc/php-fpm.d/*.conf",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_local_audit(verbose: bool = False) -> AssessmentReport:
    """Discover all local PHP installations and assess each one."""
    report = AssessmentReport(scope="local-audit")
    binaries = _discover_php_binaries()

    if not binaries:
        finding = VulnerabilityFinding(
            target="local-system",
            vuln_status=VulnStatus.UNKNOWN,
            notes=["No PHP binaries found on PATH or in common locations."],
            checks_performed=["binary-discovery"],
        )
        report.findings.append(finding)
        return report

    for binary in binaries:
        finding = _audit_binary(binary, verbose=verbose)
        report.findings.append(finding)

    return report


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _discover_php_binaries() -> list[str]:
    """Return unique, resolvable PHP binary paths."""
    found: set[str] = set()

    for pattern in _PHP_BINARY_PATTERNS:
        # Try shutil.which first (searches PATH)
        resolved = shutil.which(pattern)
        if resolved:
            found.add(os.path.realpath(resolved))
            continue
        # Glob for absolute patterns
        for match in glob.glob(pattern):
            if os.path.isfile(match) and os.access(match, os.X_OK):
                found.add(os.path.realpath(match))

    return sorted(found)


# ---------------------------------------------------------------------------
# Per-binary assessment
# ---------------------------------------------------------------------------


def _audit_binary(binary: str, verbose: bool = False) -> VulnerabilityFinding:
    finding = VulnerabilityFinding(target=binary)
    finding.checks_performed.append("php-binary-version")

    raw_version = _get_binary_version(binary)
    if raw_version is None:
        finding.notes.append(f"Could not execute {binary} or parse its output.")
        return finding

    info = parse_php_version(raw_version, source="cli")
    if info is None:
        finding.notes.append(f"Could not parse version string: {raw_version!r}")
        return finding

    finding.php_version = info
    status, conf, evidence, recs = assess_version(info)
    finding.vuln_status = status
    finding.confidence = conf
    finding.evidence.extend(evidence)
    finding.recommendations.extend(recs)

    # Additional local checks
    _check_php_ini(binary, finding, verbose=verbose)
    _check_fpm_pools(finding, verbose=verbose)

    return finding


def _get_binary_version(binary: str) -> Optional[str]:
    try:
        result = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.splitlines()[0] if result.stdout else None
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as exc:
        logger.debug("Failed to run %s --version: %s", binary, exc)
        return None


# ---------------------------------------------------------------------------
# php.ini inspection (read-only)
# ---------------------------------------------------------------------------


_RISK_SETTINGS: dict[str, dict] = {
    "session.upload_progress.enabled": {
        "risky_value": "1",
        "safe_value": "0",
        "note": (
            "session.upload_progress.enabled=1 is a known attack vector for "
            "CVE-2026-109618. Set to 0 unless strictly required."
        ),
    },
    "memory_limit": {
        "risky_value": None,  # any numeric limit is risky
        "safe_value": "-1",
        "note": (
            "A numeric memory_limit triggers the OOM path exploited by "
            "CVE-2026-109618. Consider setting memory_limit=-1 and enforcing "
            "limits at the container/cgroup level instead."
        ),
    },
    "fatal_error_backtraces": {
        "risky_value": "1",
        "safe_value": "0",
        "note": (
            "fatal_error_backtraces=1 enables the backtrace code path used in "
            "CVE-2026-109619 on PHP 8.5. Set to 0."
        ),
    },
    "expose_php": {
        "risky_value": "1",
        "safe_value": "0",
        "note": "expose_php=1 leaks version information via HTTP headers.",
    },
    "display_errors": {
        "risky_value": "1",
        "safe_value": "0",
        "note": "display_errors=1 exposes internal information in HTTP responses.",
    },
}


def _check_php_ini(binary: str, finding: VulnerabilityFinding, verbose: bool = False) -> None:
    """Locate and review the php.ini for risky settings."""
    ini_path = _get_ini_path(binary)
    if ini_path is None:
        # Fall back to glob patterns
        for pattern in _INI_PATTERNS:
            matches = glob.glob(pattern)
            if matches:
                ini_path = matches[0]
                break

    if ini_path is None or not os.path.isfile(ini_path):
        finding.notes.append("php.ini not found or not readable for this binary.")
        return

    finding.checks_performed.append(f"php-ini:{ini_path}")

    try:
        settings = _parse_ini_flat(ini_path)
    except Exception as exc:  # noqa: BLE001
        finding.notes.append(f"Could not parse {ini_path}: {exc}")
        return

    for key, meta in _RISK_SETTINGS.items():
        value = settings.get(key, "").strip().lower()
        if not value:
            continue
        risky = meta["risky_value"]
        if risky is None:
            # memory_limit: risky if NOT -1
            if value != "-1":
                finding.notes.append(f"[php.ini] {key}={value} → {meta['note']}")
                finding.recommendations.append(f"Set {key}={meta['safe_value']} in {ini_path}.")
        elif value == risky:
            finding.notes.append(f"[php.ini] {key}={value} → {meta['note']}")
            finding.recommendations.append(f"Set {key}={meta['safe_value']} in {ini_path}.")

    if verbose:
        finding.notes.append(f"php.ini reviewed: {ini_path}")


def _get_ini_path(binary: str) -> Optional[str]:
    try:
        result = subprocess.run(
            [binary, "--ini"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines():
            if "Loaded Configuration File" in line and ":" in line:
                path = line.split(":", 1)[1].strip()
                if path and os.path.isfile(path):
                    return path
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not get ini path from %s: %s", binary, exc)
    return None


def _parse_ini_flat(path: str) -> dict[str, str]:
    """Parse php.ini into a flat key→value dict (ignores sections)."""
    parser = configparser.RawConfigParser(strict=False)
    # php.ini has no section headers, so we fake one
    with open(path, encoding="utf-8", errors="replace") as fh:
        content = "[DEFAULT]\n" + fh.read()
    parser.read_string(content)
    return dict(parser.defaults())


# ---------------------------------------------------------------------------
# PHP-FPM pool checks (read-only)
# ---------------------------------------------------------------------------


def _check_fpm_pools(finding: VulnerabilityFinding, verbose: bool = False) -> None:
    pool_files: list[str] = []
    for pattern in _FPM_POOL_PATTERNS:
        pool_files.extend(glob.glob(pattern))

    if not pool_files:
        return

    finding.checks_performed.append("php-fpm-pools")
    for pool_file in pool_files:
        try:
            _check_single_fpm_pool(pool_file, finding)
        except Exception as exc:  # noqa: BLE001
            finding.notes.append(f"Could not parse FPM pool {pool_file}: {exc}")


def _check_single_fpm_pool(pool_file: str, finding: VulnerabilityFinding) -> None:
    parser = configparser.RawConfigParser()
    parser.read(pool_file, encoding="utf-8")
    for section in parser.sections():
        listen = parser.get(section, "listen", fallback="")
        if listen and not _is_local_listen(listen):
            finding.notes.append(
                f"[FPM pool {Path(pool_file).name}] Section [{section}] listens on "
                f"{listen!r} — verify this is not publicly exposed."
            )
        pm = parser.get(section, "pm", fallback="")
        if pm == "static":
            finding.notes.append(
                f"[FPM pool {Path(pool_file).name}] pm=static can accumulate stale "
                "worker state. Consider pm=dynamic or pm=ondemand for isolation."
            )


def _is_local_listen(listen: str) -> bool:
    """Return True if the listen address is clearly localhost/socket."""
    local_prefixes = ("127.", "/", "localhost", "::1", "[::1]")
    return any(listen.startswith(p) for p in local_prefixes)
