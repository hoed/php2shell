"""Shared data models for PHP2Shell Sentinel."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum


class VulnStatus(str, Enum):
    """Vulnerability determination for a target or installation."""

    VULNERABLE = "VULNERABLE"
    PATCHED = "PATCHED"
    UNSUPPORTED_EOL = "UNSUPPORTED_EOL"  # e.g. PHP 7.x, 8.0, 8.1
    UNKNOWN = "UNKNOWN"


class RemoteStatus(str, Enum):
    """Conservative status for remote (network) assessments."""

    POTENTIALLY_AFFECTED = "POTENTIALLY_AFFECTED"
    PATCHED_INDICATOR = "PATCHED_INDICATOR"
    INCONCLUSIVE = "INCONCLUSIVE"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ---------------------------------------------------------------------------
# CVE / patch data
# ---------------------------------------------------------------------------

CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")

# Official patched releases per branch (source: PHP GitHub + advisories)
PATCHED_VERSIONS: dict[str, str] = {
    "8.5": "8.5.12",
    "8.4": "8.4.27",
    "8.3": "8.3.36",
    "8.2": "8.2.35",
}

# Branches that will not receive an official fix
EOL_BRANCHES = {"8.1", "8.0", "7.4", "7.3", "7.2", "7.1", "7.0", "5"}

PATCH_DATE = "2026-10-21"
CVSS_SCORE = "9.2 (CVSS v4.0)"
ADVISORY_URLS = {
    "CVE-2026-109618": "https://github.com/advisories/GHSA-w8hw-w9fx-j79w",
    "CVE-2026-109619": "https://github.com/advisories/GHSA-6wmf-4rv5-p3rp",
}

# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class PHPVersionInfo:
    """Parsed PHP version details."""

    raw: str
    major: int
    minor: int
    patch: int
    branch: str  # e.g. "8.4"
    source: str  # "cli", "fpm", "apache", "banner", "header", etc.

    def as_tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __str__(self) -> str:
        return self.raw


@dataclass
class VulnerabilityFinding:
    """Result of assessing a single PHP installation or endpoint."""

    target: str
    timestamp: str = field(
        default_factory=lambda: (
            datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    )
    php_version: PHPVersionInfo | None = None
    vuln_status: VulnStatus = VulnStatus.UNKNOWN
    remote_status: RemoteStatus | None = None
    confidence: Confidence = Confidence.LOW
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=lambda: list(CVE_IDS))
    checks_performed: list[str] = field(default_factory=list)


@dataclass
class AssessmentReport:
    """Top-level container wrapping one or more findings."""

    scope: str
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: (
            datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    )
    toolkit_version: str = "1.0.0"
    cve_references: dict[str, str] = field(default_factory=lambda: dict(ADVISORY_URLS))
