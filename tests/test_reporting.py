"""Tests for report rendering."""

import json

from php2shell_sentinel.core.models import (
    AssessmentReport,
    VulnerabilityFinding,
    VulnStatus,
    Confidence,
    PHPVersionInfo,
)
from php2shell_sentinel.reporting.renderer import render_json, render_markdown


def _sample_report() -> AssessmentReport:
    php_info = PHPVersionInfo(
        raw="8.4.26", major=8, minor=4, patch=26, branch="8.4", source="cli"
    )
    finding = VulnerabilityFinding(
        target="test-local",
        php_version=php_info,
        vuln_status=VulnStatus.VULNERABLE,
        confidence=Confidence.HIGH,
        evidence=["PHP 8.4.26 < patched 8.4.27"],
        recommendations=["Upgrade to PHP 8.4.27"],
        notes=["Found via cli binary"],
        checks_performed=["php-binary-version"],
    )
    return AssessmentReport(scope="unit-test", findings=[finding])


class TestJsonRendering:
    def test_valid_json(self):
        report = _sample_report()
        text = render_json(report)
        parsed = json.loads(text)
        assert parsed["scope"] == "unit-test"
        assert len(parsed["findings"]) == 1

    def test_finding_fields(self):
        report = _sample_report()
        parsed = json.loads(render_json(report))
        f = parsed["findings"][0]
        assert f["target"] == "test-local"
        assert f["vuln_status"] == "VULNERABLE"
        assert f["php_version"] == "8.4.26"
        assert f["confidence"] == "HIGH"
        assert "Upgrade" in f["recommendations"][0]

    def test_write_to_file(self, tmp_path):
        report = _sample_report()
        out = str(tmp_path / "report.json")
        render_json(report, output_path=out)
        import pathlib
        content = pathlib.Path(out).read_text()
        assert "VULNERABLE" in content


class TestMarkdownRendering:
    def test_contains_cve(self):
        report = _sample_report()
        md = render_markdown(report)
        assert "CVE-2026-109618" in md
        assert "CVE-2026-109619" in md

    def test_contains_target(self):
        report = _sample_report()
        md = render_markdown(report)
        assert "test-local" in md

    def test_contains_status(self):
        report = _sample_report()
        md = render_markdown(report)
        assert "VULNERABLE" in md

    def test_contains_recommendations(self):
        report = _sample_report()
        md = render_markdown(report)
        assert "8.4.27" in md

    def test_write_to_file(self, tmp_path):
        report = _sample_report()
        out = str(tmp_path / "report.md")
        render_markdown(report, output_path=out)
        import pathlib
        assert "CVE" in pathlib.Path(out).read_text()
