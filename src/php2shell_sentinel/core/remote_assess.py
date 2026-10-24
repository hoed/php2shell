"""Conservative remote HTTP assessment for PHP version indicators.

This module ONLY reads publicly available HTTP headers and responses.
It does NOT send memory-corruption triggers, exploit payloads, or
destructive multipart requests.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

from .models import (
    AssessmentReport,
    Confidence,
    RemoteStatus,
    VulnerabilityFinding,
    VulnStatus,
    PATCHED_VERSIONS,
    EOL_BRANCHES,
)
from .version_parser import assess_version, parse_php_version
from .fingerprint import fingerprint as _fingerprint

logger = logging.getLogger(__name__)

# Sentinel user-agent — identify ourselves clearly
_USER_AGENT = (
    "PHP2Shell-Sentinel/1.0 (Security Assessment; "
    "https://github.com/your-org/php2shell-sentinel)"
)

# Headers that may leak PHP version
_PHP_HEADERS = ("x-powered-by", "server", "x-php-version")

# Default request config
DEFAULT_TIMEOUT = 10.0   # seconds
DEFAULT_RATE_LIMIT_DELAY = 1.0  # seconds between requests
MAX_TARGETS = 50  # hard limit per session


# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------


def validate_scope(target: str, allowlist: list[str]) -> bool:
    """Return True only if *target* is explicitly in the allowlist."""
    host = _extract_host(target)
    if not host:
        return False
    for allowed in allowlist:
        allowed_host = _extract_host(allowed) or allowed.strip()
        if host == allowed_host:
            return True
    return False


def _extract_host(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return parsed.hostname
    except Exception:  # noqa: BLE001
        return None


def _is_private_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Single-target assessment
# ---------------------------------------------------------------------------


def assess_remote(
    target: str,
    allowlist: list[str],
    timeout: float = DEFAULT_TIMEOUT,
    rate_limit_delay: float = DEFAULT_RATE_LIMIT_DELAY,
    verify_tls: bool = True,
) -> VulnerabilityFinding:
    """
    Perform a conservative passive assessment of *target*.

    Sends a single HEAD/GET request and analyses HTTP headers only.
    No exploit payloads are sent.
    """
    finding = VulnerabilityFinding(target=target)

    # ── scope gate ───────────────────────────────────────────────────────────
    if not validate_scope(target, allowlist):
        finding.vuln_status = VulnStatus.UNKNOWN
        finding.remote_status = RemoteStatus.INCONCLUSIVE
        finding.notes.append(
            f"Target {target!r} is NOT in the authorised allowlist. "
            "Assessment skipped. Add it to --allowlist to proceed."
        )
        return finding

    finding.checks_performed.append("scope-validation:passed")

    # ── rate limit (be a good citizen) ───────────────────────────────────────
    time.sleep(rate_limit_delay)

    # ── HTTP request ─────────────────────────────────────────────────────────
    headers_received: dict[str, str] = {}
    status_code: Optional[int] = None
    error_note: Optional[str] = None

    try:
        with httpx.Client(
            verify=verify_tls,
            timeout=timeout,
            headers={"User-Agent": _USER_AGENT},
            follow_redirects=True,
        ) as client:
            # Prefer HEAD to minimise data transfer; fall back to GET on 405
            resp = client.head(target)
            finding.checks_performed.append("http-HEAD")
            if resp.status_code == 405:
                resp = client.get(target)
                finding.checks_performed.append("http-GET")

            status_code = resp.status_code
            headers_received = dict(resp.headers)

    except httpx.TimeoutException as exc:
        error_note = f"Request to {target} timed out after {timeout}s."
    except httpx.ConnectError as exc:
        error_note = f"Connection to {target} failed: {exc}"
    except httpx.TransportError as exc:
        error_note = (
            f"Transport/TLS error for {target}: {exc}. "
            "Use --no-verify-tls only in controlled lab environments."
        )
    except Exception as exc:  # noqa: BLE001
        error_note = f"Unexpected error requesting {target}: {exc}"

    if error_note:
        finding.notes.append(error_note)
        finding.remote_status = RemoteStatus.INCONCLUSIVE
        finding.confidence = Confidence.LOW
        return finding

    finding.evidence.append(f"HTTP status: {status_code}")

    # ── header analysis ───────────────────────────────────────────────────────
    php_version_found: Optional[str] = None
    for header_name in _PHP_HEADERS:
        value = headers_received.get(header_name, "")
        if not value:
            continue
        finding.evidence.append(f"Header {header_name}: {value!r}")
        # Only treat the Server header as a PHP candidate if it contains "php"
        if header_name == "server" and "php" not in value.lower():
            continue
        if php_version_found is None:
            php_version_found = value

    if php_version_found:
        info = parse_php_version(php_version_found, source="http-header")
        if info:
            finding.php_version = info
            status, conf, evidence, recs = assess_version(info)
            finding.vuln_status = status
            finding.confidence = _downgrade_confidence(conf)  # remote = one step lower
            finding.evidence.extend(evidence)
            finding.recommendations.extend(recs)
            finding.remote_status = _map_remote_status(status)
        else:
            finding.notes.append(
                f"PHP-like header found but version not parseable: {php_version_found!r}"
            )
            finding.remote_status = RemoteStatus.INCONCLUSIVE
            finding.confidence = Confidence.LOW
    else:
        # No PHP indicator found — may be hidden or not PHP
        finding.notes.extend([
            "No PHP version header detected. Server may hide version information.",
            "Absence of PHP headers does NOT confirm the server is safe.",
            "Consider local audit or authenticated assessment for definitive results.",
        ])
        finding.remote_status = RemoteStatus.INCONCLUSIVE
        finding.confidence = Confidence.LOW

    # ── Deep passive fingerprinting (if header alone was inconclusive) ────
    if finding.remote_status == RemoteStatus.INCONCLUSIVE or finding.php_version is None:
        try:
            fp = _fingerprint(target, timeout=timeout, verify_tls=verify_tls)
            finding.checks_performed.append('deep-fingerprint')
            finding.evidence.extend(
                [f'[fingerprint] {e}' for e in fp.evidence]
            )
            if fp.version_hint and finding.php_version is None:
                finding.php_version = fp.version_hint
                status, conf, evd, recs = assess_version(fp.version_hint)
                finding.vuln_status = status
                finding.confidence = _downgrade_confidence(conf)
                finding.evidence.extend(evd)
                finding.recommendations.extend(recs)
                finding.remote_status = _map_remote_status(status)
            elif fp.php_detected and finding.remote_status == RemoteStatus.INCONCLUSIVE:
                finding.evidence.append(
                    'PHP presence inferred from fingerprinting (no version obtained)'
                )
                finding.remote_status = RemoteStatus.POTENTIALLY_AFFECTED
                finding.confidence = Confidence.LOW
                finding.notes.append(
                    'PHP detected via deep fingerprinting but version could not be '
                    'determined. Manual verification recommended.'
                )
        except Exception as _fp_exc:  # noqa: BLE001
            logger.debug('Fingerprint probe failed: %s', _fp_exc)

    _add_universal_recommendations(finding)
    return finding


# ---------------------------------------------------------------------------
# Batch assessment
# ---------------------------------------------------------------------------


def assess_remote_batch(
    targets: list[str],
    allowlist: list[str],
    timeout: float = DEFAULT_TIMEOUT,
    rate_limit_delay: float = DEFAULT_RATE_LIMIT_DELAY,
    verify_tls: bool = True,
) -> AssessmentReport:
    """Assess multiple targets and collect into a single report."""
    if len(targets) > MAX_TARGETS:
        raise ValueError(
            f"Too many targets ({len(targets)}). "
            f"Maximum per session is {MAX_TARGETS}."
        )

    report = AssessmentReport(scope=f"remote-assess:{','.join(targets[:3])}...")
    for target in targets:
        finding = assess_remote(
            target,
            allowlist=allowlist,
            timeout=timeout,
            rate_limit_delay=rate_limit_delay,
            verify_tls=verify_tls,
        )
        report.findings.append(finding)
    return report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _map_remote_status(status: VulnStatus) -> RemoteStatus:
    mapping = {
        VulnStatus.VULNERABLE: RemoteStatus.POTENTIALLY_AFFECTED,
        VulnStatus.PATCHED: RemoteStatus.PATCHED_INDICATOR,
        VulnStatus.UNSUPPORTED_EOL: RemoteStatus.POTENTIALLY_AFFECTED,
        VulnStatus.UNKNOWN: RemoteStatus.INCONCLUSIVE,
    }
    return mapping.get(status, RemoteStatus.INCONCLUSIVE)


def _downgrade_confidence(conf: Confidence) -> Confidence:
    """Remote assessments based on HTTP headers are inherently less certain."""
    if conf == Confidence.HIGH:
        return Confidence.MEDIUM
    return Confidence.LOW


def _add_universal_recommendations(finding: VulnerabilityFinding) -> None:
    universal = [
        "Consult official PHP advisories: https://www.php.net/security",
        "CVE-2026-109618: https://github.com/advisories/GHSA-w8hw-w9fx-j79w",
        "CVE-2026-109619: https://github.com/advisories/GHSA-6wmf-4rv5-p3rp",
    ]
    for rec in universal:
        if rec not in finding.recommendations:
            finding.recommendations.append(rec)
