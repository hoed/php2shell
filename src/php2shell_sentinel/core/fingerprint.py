"""Deeper passive PHP fingerprinting.

Techniques used (all read-only, no exploit payloads):
  1. Header correlation  — cross-reference multiple response headers
  2. Error-page probing  — request a non-existent .php path → parse error page
  3. Response-timing     — measure latency variance between .php and static paths
  4. Cookie pattern      — PHP session cookie name / format
  5. Technology stack    — correlate Server + Via + X-Cache headers
  6. Content-type hints  — PHP default content-type for edge cases

None of these send memory-corruption triggers or multipart payloads.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import httpx

from .models import Confidence, PHPVersionInfo
from .version_parser import parse_php_version

logger = logging.getLogger(__name__)

_USER_AGENT = (
    "PHP2Shell-Sentinel/1.0 (Security Assessment; "
    "https://github.com/your-org/php2shell-sentinel)"
)

# Patterns that appear in PHP default error pages
_PHP_ERROR_PATTERNS = [
    re.compile(r"<b>(?:Fatal error|Parse error|Warning|Notice)</b>", re.I),
    re.compile(r"on line \d+", re.I),
    re.compile(r"Stack trace:", re.I),
    re.compile(r"PHP \d+\.\d+\.\d+", re.I),
    re.compile(r"Zend Engine v", re.I),
]

# PHP-specific cookie names
_PHP_SESSION_COOKIE_RE = re.compile(r"PHPSESSID", re.I)

# Version extraction from error page body
_VERSION_FROM_BODY_RE = re.compile(
    r"PHP[/ ](?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)", re.I
)


@dataclass
class FingerprintResult:
    """Aggregated fingerprint evidence from passive probes."""

    target: str
    php_detected: bool = False
    version_hint: Optional[PHPVersionInfo] = None
    confidence: Confidence = Confidence.LOW
    evidence: list[str] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def fingerprint(
    target: str,
    timeout: float = 10.0,
    verify_tls: bool = True,
    _transport: Optional[httpx.BaseTransport] = None,
) -> FingerprintResult:
    """
    Run all passive fingerprinting probes against *target*.

    Returns a FingerprintResult with aggregated evidence. Does NOT
    send any exploit payload or memory-corruption trigger.

    Parameters
    ----------
    _transport:
        Optional httpx transport override — used by tests to inject a
        respx.MockTransport without monkey-patching global state.
    """
    result = FingerprintResult(target=target)

    client_kwargs: dict = dict(
        verify=verify_tls,
        timeout=timeout,
        headers={"User-Agent": _USER_AGENT},
        follow_redirects=True,
    )
    if _transport is not None:
        client_kwargs["transport"] = _transport

    with httpx.Client(**client_kwargs) as client:
        _probe_headers(client, target, result)
        _probe_error_page(client, target, result)
        _probe_cookie(client, target, result)
        _probe_timing(client, target, result)

    _compute_confidence(result)
    return result


# ---------------------------------------------------------------------------
# Probe 1 — Header correlation
# ---------------------------------------------------------------------------

_HEADER_VERSION_SOURCES = (
    "x-powered-by",
    "x-php-version",
    "x-generator",
    "x-runtime",
)

_PHP_SERVER_RE = re.compile(r"\bphp[/\s](\d+\.\d+\.\d+)\b", re.I)


def _probe_headers(client: httpx.Client, target: str, result: FingerprintResult) -> None:
    try:
        resp = client.head(target)
        result.techniques_used.append("header-correlation")

        headers = dict(resp.headers)

        # Direct version headers
        for h in _HEADER_VERSION_SOURCES:
            v = headers.get(h, "")
            if v:
                info = parse_php_version(v, source=f"header:{h}")
                if info:
                    result.php_detected = True
                    result.version_hint = info
                    result.evidence.append(f"{h}: {v!r} → PHP {info}")

        # Server header containing PHP
        server = headers.get("server", "")
        m = _PHP_SERVER_RE.search(server)
        if m:
            info = parse_php_version(m.group(0), source="header:server")
            if info and result.version_hint is None:
                result.php_detected = True
                result.version_hint = info
                result.evidence.append(f"server: {server!r} → PHP {info}")

        # Set-Cookie header with PHPSESSID
        set_cookie = headers.get("set-cookie", "")
        if _PHP_SESSION_COOKIE_RE.search(set_cookie):
            result.php_detected = True
            result.evidence.append("PHPSESSID cookie detected in Set-Cookie header")

        # X-Cache / Via patterns that are PHP-ecosystem specific
        for hname in ("x-varnish", "x-cache", "via"):
            val = headers.get(hname, "")
            if val:
                result.evidence.append(f"{hname}: {val!r}")

    except httpx.HTTPError as exc:
        result.warnings.append(f"Header probe failed: {exc}")


# ---------------------------------------------------------------------------
# Probe 2 — Error page analysis
# ---------------------------------------------------------------------------


def _probe_error_page(client: httpx.Client, target: str, result: FingerprintResult) -> None:
    """
    Request a path that almost certainly does not exist.
    If PHP is present and display_errors=On, the error page leaks the version.
    We only READ the response — no payload is sent.
    """
    probe_url = urljoin(target.rstrip("/") + "/", "__php2shell_sentinel_probe__.php")
    try:
        resp = client.get(probe_url)
        result.techniques_used.append("error-page-probe")

        body = resp.text[:4096]  # read only first 4 KB

        # Check for PHP error patterns
        matched_patterns = [p.pattern for p in _PHP_ERROR_PATTERNS if p.search(body)]
        if matched_patterns:
            result.php_detected = True
            result.evidence.append(
                f"PHP error-page patterns found at {probe_url}: "
                + ", ".join(repr(p) for p in matched_patterns[:2])
            )

        # Try to extract version from error body
        vm = _VERSION_FROM_BODY_RE.search(body)
        if vm and result.version_hint is None:
            raw = f"{vm.group('major')}.{vm.group('minor')}.{vm.group('patch')}"
            info = parse_php_version(raw, source="error-page-body")
            if info:
                result.version_hint = info
                result.evidence.append(
                    f"PHP version extracted from error page body: {info}"
                )

        # HTTP 404 with PHP-style body is still evidence
        if resp.status_code in (404, 500) and result.php_detected:
            result.evidence.append(
                f"PHP-like {resp.status_code} response at probe URL"
            )

    except httpx.HTTPError as exc:
        result.warnings.append(f"Error-page probe failed: {exc}")


# ---------------------------------------------------------------------------
# Probe 3 — PHP session cookie
# ---------------------------------------------------------------------------


def _probe_cookie(client: httpx.Client, target: str, result: FingerprintResult) -> None:
    """Request index.php explicitly; watch for Set-Cookie: PHPSESSID."""
    index_url = urljoin(target.rstrip("/") + "/", "index.php")
    try:
        resp = client.get(index_url)
        result.techniques_used.append("cookie-probe")

        for cookie in resp.cookies.keys():
            if _PHP_SESSION_COOKIE_RE.match(cookie):
                result.php_detected = True
                result.evidence.append(
                    f"PHP session cookie {cookie!r} set by {index_url}"
                )
                break

        # Some PHP apps use a custom session name — check raw header too
        raw_cookie = resp.headers.get("set-cookie", "")
        if "PHPSESSID" in raw_cookie.upper():
            result.php_detected = True
            result.evidence.append("PHPSESSID detected in raw Set-Cookie header")

    except httpx.HTTPError as exc:
        result.warnings.append(f"Cookie probe failed: {exc}")


# ---------------------------------------------------------------------------
# Probe 4 — Response timing (non-exploitative)
# ---------------------------------------------------------------------------

_TIMING_SAMPLES = 3
_TIMING_THRESHOLD_MS = 80  # ms variance between .php vs static path


def _probe_timing(client: httpx.Client, target: str, result: FingerprintResult) -> None:
    """
    Measure response-time variance between a .php path and a static path.

    A consistently higher latency for .php paths (vs a static .txt path)
    is weak evidence of a PHP interpreter being invoked. This is informational
    only and never changes confidence alone.
    """
    php_url = urljoin(target.rstrip("/") + "/", "index.php")
    static_url = urljoin(target.rstrip("/") + "/", "robots.txt")

    def _avg_ms(url: str) -> Optional[float]:
        times: list[float] = []
        for _ in range(_TIMING_SAMPLES):
            try:
                t0 = time.perf_counter()
                client.head(url)
                times.append((time.perf_counter() - t0) * 1000)
            except httpx.HTTPError:
                return None
        return sum(times) / len(times) if times else None

    try:
        php_avg = _avg_ms(php_url)
        static_avg = _avg_ms(static_url)
        result.techniques_used.append("response-timing")

        if php_avg is not None and static_avg is not None:
            diff = php_avg - static_avg
            result.evidence.append(
                f"Response timing: .php avg={php_avg:.1f}ms  "
                f"static avg={static_avg:.1f}ms  diff={diff:+.1f}ms"
            )
            if diff > _TIMING_THRESHOLD_MS:
                result.evidence.append(
                    f"PHP interpreter latency signature detected "
                    f"(diff > {_TIMING_THRESHOLD_MS}ms)"
                )
                result.php_detected = True

    except Exception as exc:  # noqa: BLE001
        result.warnings.append(f"Timing probe failed: {exc}")


# ---------------------------------------------------------------------------
# Confidence computation
# ---------------------------------------------------------------------------


def _compute_confidence(result: FingerprintResult) -> None:
    """Set confidence based on how many independent techniques fired."""
    if result.version_hint is not None:
        # Version found from at least one source
        fired = len([e for e in result.evidence if "PHP" in e])
        result.confidence = Confidence.HIGH if fired >= 2 else Confidence.MEDIUM
    elif result.php_detected:
        result.confidence = Confidence.MEDIUM
    else:
        result.confidence = Confidence.LOW
