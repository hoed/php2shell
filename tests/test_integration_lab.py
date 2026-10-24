"""
Integration tests — run against the real Docker lab (no mocks).

Requirements
------------
  cd lab && docker compose up -d
  # wait ~5 seconds for containers to start
  php2shell-sentinel lab-check

Skip gracefully when lab is not running so CI (which has no Docker lab)
still passes. Set environment variable PHP2SHELL_LAB=1 to force-enable.

Usage
-----
  # With lab running:
  PHP2SHELL_LAB=1 pytest tests/test_integration_lab.py -v

  # Without lab (skipped automatically):
  pytest tests/test_integration_lab.py -v
"""

from __future__ import annotations

import os
import socket
import time

import httpx
import pytest

from php2shell_sentinel.core.remote_assess import assess_remote
from php2shell_sentinel.core.models import RemoteStatus, VulnStatus
from php2shell_sentinel.core.version_parser import parse_php_version, assess_version
from php2shell_sentinel.core.local_audit import run_local_audit

# Lab container addresses (must match lab/docker-compose.yml)
LAB_PATCHED_URL   = "http://127.0.0.1:8880"
LAB_VULNERABLE_URL = "http://127.0.0.1:8881"

FORCE_LAB = os.environ.get("PHP2SHELL_LAB", "").strip() == "1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if the TCP port accepts connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _lab_available(url: str) -> bool:
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return _port_open(parsed.hostname or "127.0.0.1", port)


def lab_required(url: str):
    """Pytest mark: skip unless FORCE_LAB=1 or the container port is open."""
    available = FORCE_LAB or _lab_available(url)
    return pytest.mark.skipif(
        not available,
        reason=f"Lab container not running at {url}. "
               "Start with: cd lab && docker compose up -d  "
               "Then re-run with PHP2SHELL_LAB=1",
    )


# ---------------------------------------------------------------------------
# Patched container
# ---------------------------------------------------------------------------

@lab_required(LAB_PATCHED_URL)
class TestPatchedContainer:
    """Assess the patched lab container — expect PATCHED_INDICATOR."""

    def test_remote_status_patched(self):
        finding = assess_remote(
            LAB_PATCHED_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        assert finding.remote_status == RemoteStatus.PATCHED_INDICATOR, (
            f"Expected PATCHED_INDICATOR, got {finding.remote_status}. "
            f"Notes: {finding.notes}"
        )

    def test_version_detected(self):
        finding = assess_remote(
            LAB_PATCHED_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        assert finding.php_version is not None, (
            "PHP version not detected from patched container. "
            "Check that expose_php is On and X-Powered-By is set in lab/www/patched/index.php"
        )

    def test_version_is_patched_release(self):
        finding = assess_remote(
            LAB_PATCHED_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        if finding.php_version is None:
            pytest.skip("PHP version not exposed by patched container")
        status, _, _, _ = assess_version(finding.php_version)
        assert status == VulnStatus.PATCHED

    def test_confidence_at_least_medium(self):
        from php2shell_sentinel.core.models import Confidence
        finding = assess_remote(
            LAB_PATCHED_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        assert finding.confidence in (Confidence.MEDIUM, Confidence.HIGH)


# ---------------------------------------------------------------------------
# Vulnerable container
# ---------------------------------------------------------------------------

@lab_required(LAB_VULNERABLE_URL)
class TestVulnerableContainer:
    """Assess the vulnerable lab container — expect POTENTIALLY_AFFECTED."""

    def test_remote_status_vulnerable(self):
        finding = assess_remote(
            LAB_VULNERABLE_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        assert finding.remote_status == RemoteStatus.POTENTIALLY_AFFECTED, (
            f"Expected POTENTIALLY_AFFECTED, got {finding.remote_status}. "
            f"Notes: {finding.notes}"
        )

    def test_version_older_than_patched(self):
        finding = assess_remote(
            LAB_VULNERABLE_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        if finding.php_version is None:
            pytest.skip("PHP version not exposed by vulnerable container")
        # Should be < 8.4.27
        assert finding.php_version.as_tuple() < (8, 4, 27)

    def test_recommendations_present(self):
        finding = assess_remote(
            LAB_VULNERABLE_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        assert len(finding.recommendations) > 0

    def test_cves_listed(self):
        finding = assess_remote(
            LAB_VULNERABLE_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        assert "CVE-2026-109618" in finding.cves
        assert "CVE-2026-109619" in finding.cves


# ---------------------------------------------------------------------------
# Differential: patched vs vulnerable
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not (
        (FORCE_LAB or _lab_available(LAB_PATCHED_URL))
        and (FORCE_LAB or _lab_available(LAB_VULNERABLE_URL))
    ),
    reason="Both lab containers must be running for differential test.",
)
class TestDifferential:
    """Confirm patched and vulnerable containers produce different results."""

    def test_statuses_differ(self):
        patched = assess_remote(
            LAB_PATCHED_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        vulnerable = assess_remote(
            LAB_VULNERABLE_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        assert patched.remote_status != vulnerable.remote_status, (
            "Patched and vulnerable containers returned the same status — "
            "detection logic may not be working correctly."
        )

    def test_patched_version_newer(self):
        patched = assess_remote(
            LAB_PATCHED_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        vulnerable = assess_remote(
            LAB_VULNERABLE_URL,
            allowlist=["127.0.0.1"],
            rate_limit_delay=0,
            verify_tls=False,
        )
        if patched.php_version is None or vulnerable.php_version is None:
            pytest.skip("Version not exposed by one or both containers")
        assert patched.php_version.as_tuple() > vulnerable.php_version.as_tuple()


# ---------------------------------------------------------------------------
# Local audit integration (no Docker required — runs on the host)
# ---------------------------------------------------------------------------

class TestLocalAuditIntegration:
    """Run the local auditor on the test host.

    We cannot assert a specific PHP version since CI hosts vary,
    but we can assert the report structure is always valid.
    """

    def test_report_has_findings(self):
        report = run_local_audit()
        assert len(report.findings) >= 1

    def test_all_findings_have_target(self):
        report = run_local_audit()
        for f in report.findings:
            assert f.target, "Finding has no target field"

    def test_all_findings_have_timestamp(self):
        report = run_local_audit()
        for f in report.findings:
            assert f.timestamp.endswith("Z"), f"Bad timestamp: {f.timestamp}"

    def test_all_findings_have_cves(self):
        report = run_local_audit()
        for f in report.findings:
            assert "CVE-2026-109618" in f.cves
            assert "CVE-2026-109619" in f.cves

    def test_vuln_status_is_valid_enum(self):
        from php2shell_sentinel.core.models import VulnStatus
        report = run_local_audit()
        valid = set(VulnStatus)
        for f in report.findings:
            assert f.vuln_status in valid, f"Invalid status: {f.vuln_status}"

    def test_no_secrets_in_report(self):
        """Ensure nothing that looks like a secret leaks into the report."""
        import json
        from php2shell_sentinel.reporting.renderer import render_json
        report = run_local_audit()
        text = render_json(report).lower()
        for bad in ("password", "secret", "token", "private_key", "-----begin"):
            assert bad not in text, f"Potential secret leaked into report: {bad!r}"
