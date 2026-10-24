"""Tests for remote_assess module."""

import httpx
import pytest
import respx

from php2shell_sentinel.core.models import RemoteStatus, VulnStatus
from php2shell_sentinel.core.remote_assess import (
    MAX_TARGETS,
    assess_remote,
    assess_remote_batch,
    validate_scope,
)

# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------


class TestValidateScope:
    def test_exact_match(self):
        assert validate_scope("https://example.com/path", ["example.com"]) is True

    def test_no_match(self):
        assert validate_scope("https://evil.com", ["example.com"]) is False

    def test_empty_allowlist(self):
        assert validate_scope("https://example.com", []) is False

    def test_multiple_allowlist_entries(self):
        assert (
            validate_scope("https://target.example.org", ["other.com", "target.example.org"])
            is True
        )

    def test_subdomain_not_parent(self):
        # "example.com" in allowlist should NOT match "evil.example.com"
        assert validate_scope("https://evil.example.com", ["example.com"]) is False

    def test_invalid_url(self):
        assert validate_scope("not-a-url", ["example.com"]) is False


# ---------------------------------------------------------------------------
# Remote assess — mocked HTTP (use respx.mock as context manager, not decorator)
# ---------------------------------------------------------------------------


class TestAssessRemote:
    def test_vulnerable_version_in_header(self):
        with respx.mock:
            respx.head("https://example.com/").mock(
                return_value=httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.26"})
            )
            finding = assess_remote(
                "https://example.com/",
                allowlist=["example.com"],
                rate_limit_delay=0,
            )
        assert finding.remote_status == RemoteStatus.POTENTIALLY_AFFECTED
        assert finding.php_version is not None
        assert finding.php_version.patch == 26

    def test_patched_version_in_header(self):
        with respx.mock:
            respx.head("https://example.com/").mock(
                return_value=httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.27"})
            )
            finding = assess_remote(
                "https://example.com/",
                allowlist=["example.com"],
                rate_limit_delay=0,
            )
        assert finding.remote_status == RemoteStatus.PATCHED_INDICATOR

    def test_no_php_header(self):
        with respx.mock:
            respx.head("https://example.com/").mock(
                return_value=httpx.Response(200, headers={"Server": "nginx"})
            )
            finding = assess_remote(
                "https://example.com/",
                allowlist=["example.com"],
                rate_limit_delay=0,
            )
        assert finding.remote_status == RemoteStatus.INCONCLUSIVE
        assert finding.php_version is None
        assert any("Absence" in n for n in finding.notes)

    def test_target_not_in_allowlist(self):
        finding = assess_remote(
            "https://notallowed.com/",
            allowlist=["example.com"],
            rate_limit_delay=0,
        )
        assert finding.remote_status == RemoteStatus.INCONCLUSIVE
        assert any("NOT in the authorised" in n for n in finding.notes)

    def test_timeout_handled_gracefully(self):
        with respx.mock:
            respx.head("https://example.com/").mock(side_effect=httpx.TimeoutException("timed out"))
            finding = assess_remote(
                "https://example.com/",
                allowlist=["example.com"],
                rate_limit_delay=0,
            )
        assert finding.remote_status == RemoteStatus.INCONCLUSIVE
        assert any("timed out" in n.lower() for n in finding.notes)

    def test_connection_error_handled(self):
        with respx.mock:
            respx.head("https://example.com/").mock(side_effect=httpx.ConnectError("refused"))
            finding = assess_remote(
                "https://example.com/",
                allowlist=["example.com"],
                rate_limit_delay=0,
            )
        assert finding.remote_status == RemoteStatus.INCONCLUSIVE

    def test_batch_too_many_targets(self):
        targets = [f"https://target{i}.com/" for i in range(MAX_TARGETS + 1)]
        allowlist = [f"target{i}.com" for i in range(MAX_TARGETS + 1)]
        with pytest.raises(ValueError, match="Too many targets"):
            assess_remote_batch(targets, allowlist=allowlist, rate_limit_delay=0)

    def test_eol_version_in_header(self):
        with respx.mock:
            respx.head("https://example.com/").mock(
                return_value=httpx.Response(200, headers={"X-Powered-By": "PHP/7.4.33"})
            )
            finding = assess_remote(
                "https://example.com/",
                allowlist=["example.com"],
                rate_limit_delay=0,
            )
        assert finding.remote_status == RemoteStatus.POTENTIALLY_AFFECTED
        assert finding.vuln_status == VulnStatus.UNSUPPORTED_EOL
