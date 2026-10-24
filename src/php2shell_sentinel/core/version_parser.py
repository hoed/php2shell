"""PHP version parsing and patch-level comparison."""

from __future__ import annotations

import re
from typing import Optional

from .models import (
    PATCHED_VERSIONS,
    EOL_BRANCHES,
    Confidence,
    PHPVersionInfo,
    VulnStatus,
)

# Matches: "PHP 8.4.26", "PHP/8.3.35-1+deb12", "8.5.12" (bare numeric), "8.5.12RC1"
# Must NOT match "Apache/2.4.58" (no PHP prefix and major < 5 is never valid PHP)
_PHP_RE = re.compile(
    r"(?i)"
    r"(?:(?P<php_prefix>php)[/ -]?)?"       # optional "PHP" prefix
    r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?P<suffix>[a-z0-9._+-]*)?"
)


def parse_php_version(raw: str, source: str = "unknown") -> Optional[PHPVersionInfo]:
    """Extract a PHPVersionInfo from an arbitrary string, or return None."""
    m = _PHP_RE.search(raw.strip())
    if not m:
        return None
    # Require either an explicit "php" prefix OR a major version in the PHP range (5–9)
    # to avoid matching version numbers in non-PHP strings like "Apache/2.4.58"
    has_prefix = bool(m.group("php_prefix"))
    major = int(m.group("major"))
    if not has_prefix and (major < 5 or major > 9):
        return None
    minor = int(m.group("minor"))
    patch = int(m.group("patch"))
    branch = f"{major}.{minor}"
    return PHPVersionInfo(
        raw=f"{major}.{minor}.{patch}",
        major=major,
        minor=minor,
        patch=patch,
        branch=branch,
        source=source,
    )


def assess_version(
    info: PHPVersionInfo,
) -> tuple[VulnStatus, Confidence, list[str], list[str]]:
    """
    Compare *info* against the official patch matrix.

    Returns
    -------
    (status, confidence, evidence_lines, recommendations)
    """
    evidence: list[str] = []
    recommendations: list[str] = []
    branch = info.branch

    # ── EOL check first ──────────────────────────────────────────────────────
    if branch in EOL_BRANCHES or info.major < 8:
        evidence.append(
            f"PHP {info} is on an end-of-life branch ({branch}). "
            "No official patch will be released."
        )
        recommendations.extend([
            f"Upgrade to a supported PHP branch (8.2, 8.3, 8.4, or 8.5).",
            "Apply any distribution-provided backport if available (Debian LTS, RHEL, etc.).",
            "Apply temporary mitigations: memory_limit=-1, "
            "session.upload_progress.enabled=0, fatal_error_backtraces=0.",
        ])
        return VulnStatus.UNSUPPORTED_EOL, Confidence.HIGH, evidence, recommendations

    # ── Supported branch ─────────────────────────────────────────────────────
    if branch not in PATCHED_VERSIONS:
        evidence.append(f"Branch {branch} is not in the known patch matrix.")
        recommendations.append("Check https://www.php.net/downloads for the latest release.")
        return VulnStatus.UNKNOWN, Confidence.LOW, evidence, recommendations

    patched_raw = PATCHED_VERSIONS[branch]
    patched = _parse_tuple(patched_raw)
    current = info.as_tuple()

    if current >= patched:
        evidence.append(
            f"PHP {info} >= patched release {patched_raw} on branch {branch}."
        )
        return VulnStatus.PATCHED, Confidence.HIGH, evidence, recommendations
    else:
        evidence.append(
            f"PHP {info} < patched release {patched_raw} on branch {branch}."
        )
        recommendations.extend([
            f"Upgrade to PHP {patched_raw} immediately (released 2026-10-21).",
            "Apply WAF rules to restrict session upload-progress endpoints.",
            "Set memory_limit=-1 as a partial mitigation for CVE-2026-109618.",
            "Set session.upload_progress.enabled=0 in php.ini.",
            "Set fatal_error_backtraces=0 in php.ini.",
            "Monitor https://www.php.net/ChangeLog-8.php for follow-up patches.",
        ])
        return VulnStatus.VULNERABLE, Confidence.HIGH, evidence, recommendations


# ── helpers ──────────────────────────────────────────────────────────────────


def _parse_tuple(version_str: str) -> tuple[int, int, int]:
    parts = version_str.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))
