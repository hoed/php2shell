"""Tests for version_parser module."""

import pytest

from php2shell_sentinel.core.version_parser import parse_php_version, assess_version
from php2shell_sentinel.core.models import VulnStatus, Confidence


# ---------------------------------------------------------------------------
# parse_php_version
# ---------------------------------------------------------------------------

class TestParsePhpVersion:
    def test_plain_version(self):
        info = parse_php_version("8.4.26")
        assert info is not None
        assert info.major == 8
        assert info.minor == 4
        assert info.patch == 26
        assert info.branch == "8.4"

    def test_php_prefix(self):
        info = parse_php_version("PHP 8.3.35")
        assert info is not None
        assert info.major == 8
        assert info.minor == 3
        assert info.patch == 35

    def test_banner_string(self):
        raw = "PHP 8.5.11 (cli) (built: Oct 15 2026 12:00:00)"
        info = parse_php_version(raw, source="cli")
        assert info is not None
        assert info.major == 8
        assert info.minor == 5
        assert info.patch == 11
        assert info.source == "cli"

    def test_debian_suffix(self):
        info = parse_php_version("8.2.34-1+deb12u1")
        assert info is not None
        assert info.patch == 34

    def test_x_powered_by_header(self):
        info = parse_php_version("PHP/8.4.26", source="http-header")
        assert info is not None
        assert info.patch == 26
        assert info.source == "http-header"

    def test_empty_string(self):
        assert parse_php_version("") is None

    def test_no_version(self):
        assert parse_php_version("Apache/2.4.58") is None

    def test_php7(self):
        info = parse_php_version("PHP 7.4.33")
        assert info is not None
        assert info.branch == "7.4"


# ---------------------------------------------------------------------------
# assess_version
# ---------------------------------------------------------------------------

class TestAssessVersion:
    def _info(self, raw: str, source: str = "cli"):
        info = parse_php_version(raw, source=source)
        assert info is not None
        return info

    # Vulnerable versions
    @pytest.mark.parametrize("raw", [
        "8.5.11", "8.4.26", "8.3.35", "8.2.34",
        "8.5.0", "8.4.1", "8.3.0",
    ])
    def test_vulnerable(self, raw: str):
        status, conf, evidence, recs = assess_version(self._info(raw))
        assert status == VulnStatus.VULNERABLE
        assert conf == Confidence.HIGH
        assert any("Upgrade" in r or "upgrade" in r for r in recs)

    # Patched versions
    @pytest.mark.parametrize("raw", [
        "8.5.12", "8.4.27", "8.3.36", "8.2.35",
        "8.5.13", "8.4.28",  # future releases should also be PATCHED
    ])
    def test_patched(self, raw: str):
        status, conf, evidence, recs = assess_version(self._info(raw))
        assert status == VulnStatus.PATCHED
        assert conf == Confidence.HIGH

    # EOL versions
    @pytest.mark.parametrize("raw", [
        "8.1.29", "8.0.30", "7.4.33", "7.3.0", "5.6.40",
    ])
    def test_eol(self, raw: str):
        status, conf, evidence, recs = assess_version(self._info(raw))
        assert status == VulnStatus.UNSUPPORTED_EOL
        assert conf == Confidence.HIGH
        assert any("Upgrade" in r or "supported" in r for r in recs)

    def test_recommendations_include_mitigations(self):
        info = self._info("8.4.26")
        _, _, _, recs = assess_version(info)
        joined = " ".join(recs).lower()
        assert "memory_limit" in joined
        assert "upload_progress" in joined


# ---------------------------------------------------------------------------
# patch comparison edge-cases
# ---------------------------------------------------------------------------

class TestPatchComparison:
    def test_exact_patched_boundary(self):
        """Version exactly at patch boundary should be PATCHED."""
        info = parse_php_version("8.3.36")
        status, _, _, _ = assess_version(info)
        assert status == VulnStatus.PATCHED

    def test_one_below_boundary(self):
        info = parse_php_version("8.3.35")
        status, _, _, _ = assess_version(info)
        assert status == VulnStatus.VULNERABLE
