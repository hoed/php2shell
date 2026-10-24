"""Report rendering: terminal (Rich), JSON, and Markdown."""

from __future__ import annotations

import dataclasses
import json
import textwrap
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from ..core.models import (
    AssessmentReport,
    VulnerabilityFinding,
    VulnStatus,
    RemoteStatus,
    Confidence,
    CVE_IDS,
    CVSS_SCORE,
    PATCHED_VERSIONS,
    ADVISORY_URLS,
)

console = Console()

# Status → colour mapping
_VULN_COLOUR = {
    VulnStatus.VULNERABLE: "bold red",
    VulnStatus.PATCHED: "bold green",
    VulnStatus.UNSUPPORTED_EOL: "bold yellow",
    VulnStatus.UNKNOWN: "dim",
}

_REMOTE_COLOUR = {
    RemoteStatus.POTENTIALLY_AFFECTED: "bold red",
    RemoteStatus.PATCHED_INDICATOR: "bold green",
    RemoteStatus.INCONCLUSIVE: "yellow",
}


# ---------------------------------------------------------------------------
# Terminal (Rich)
# ---------------------------------------------------------------------------


def print_report_terminal(report: AssessmentReport) -> None:
    console.rule("[bold cyan]PHP2Shell Sentinel — Assessment Report[/]")
    console.print(f"[dim]Scope:[/] {report.scope}")
    console.print(f"[dim]Generated:[/] {report.generated_at}")
    console.print(f"[dim]Toolkit:[/] v{report.toolkit_version}")
    console.print()

    # CVE summary box
    _print_cve_summary()

    for i, finding in enumerate(report.findings, 1):
        _print_finding(i, finding)

    console.print()
    console.rule("[dim]End of report[/]")


def _print_cve_summary() -> None:
    table = Table(title="Tracked CVEs", box=box.ROUNDED, show_lines=True)
    table.add_column("CVE ID", style="bold")
    table.add_column("CVSS v4.0", justify="center")
    table.add_column("Patched In")
    table.add_column("Advisory")

    patches = ", ".join(f"{b}: {v}" for b, v in PATCHED_VERSIONS.items())
    for cve in CVE_IDS:
        table.add_row(cve, CVSS_SCORE, patches, ADVISORY_URLS.get(cve, ""))
    console.print(table)
    console.print()


def _print_finding(index: int, f: VulnerabilityFinding) -> None:
    # Status determination
    if f.remote_status is not None:
        colour = _REMOTE_COLOUR.get(f.remote_status, "dim")
        status_str = f.remote_status.value
    else:
        colour = _VULN_COLOUR.get(f.vuln_status, "dim")
        status_str = f.vuln_status.value

    version_str = str(f.php_version) if f.php_version else "not detected"
    conf_str = f.confidence.value if f.confidence else "UNKNOWN"

    title = Text()
    title.append(f"[{index}] ", style="dim")
    title.append(f.target, style="bold")
    title.append(f"  [{status_str}]", style=colour)

    panel_content = []
    panel_content.append(f"[dim]Timestamp:[/] {f.timestamp}")
    panel_content.append(f"[dim]PHP version:[/] {version_str}")
    panel_content.append(f"[dim]Status:[/] [{colour}]{status_str}[/]")
    panel_content.append(f"[dim]Confidence:[/] {conf_str}")

    if f.checks_performed:
        panel_content.append(f"[dim]Checks:[/] {', '.join(f.checks_performed)}")

    if f.evidence:
        panel_content.append("\n[bold]Evidence:[/]")
        for e in f.evidence:
            panel_content.append(f"  • {e}")

    if f.notes:
        panel_content.append("\n[bold yellow]Notes:[/]")
        for n in f.notes:
            panel_content.append(f"  ⚠  {n}")

    if f.recommendations:
        panel_content.append("\n[bold green]Recommendations:[/]")
        for r in f.recommendations:
            panel_content.append(f"  → {r}")

    console.print(
        Panel(
            "\n".join(panel_content),
            title=title,
            border_style=colour,
            expand=False,
            padding=(0, 2),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def render_json(report: AssessmentReport, output_path: Optional[str] = None) -> str:
    """Serialise report to JSON. Writes to file if output_path given."""

    def _default(obj):  # noqa: ANN001
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return dataclasses.asdict(obj)
        if hasattr(obj, "value"):  # Enum
            return obj.value
        return str(obj)

    payload = {
        "toolkit_version": report.toolkit_version,
        "generated_at": report.generated_at,
        "scope": report.scope,
        "cve_references": report.cve_references,
        "findings": [_serialise_finding(f) for f in report.findings],
    }
    text = json.dumps(payload, indent=2, default=_default)
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
    return text


def _serialise_finding(f: VulnerabilityFinding) -> dict:
    return {
        "target": f.target,
        "timestamp": f.timestamp,
        "php_version": str(f.php_version) if f.php_version else None,
        "php_version_source": f.php_version.source if f.php_version else None,
        "vuln_status": f.vuln_status.value,
        "remote_status": f.remote_status.value if f.remote_status else None,
        "confidence": f.confidence.value,
        "cves": f.cves,
        "checks_performed": f.checks_performed,
        "evidence": f.evidence,
        "notes": f.notes,
        "recommendations": f.recommendations,
    }


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def render_markdown(report: AssessmentReport, output_path: Optional[str] = None) -> str:
    lines: list[str] = [
        "# PHP2Shell Sentinel — Assessment Report",
        "",
        f"**Scope:** {report.scope}  ",
        f"**Generated:** {report.generated_at}  ",
        f"**Toolkit version:** {report.toolkit_version}  ",
        "",
        "## Tracked CVEs",
        "",
        "| CVE | CVSS v4.0 | Patched In |",
        "| --- | --------- | ---------- |",
    ]
    patches = " / ".join(f"{b}: {v}" for b, v in PATCHED_VERSIONS.items())
    for cve in CVE_IDS:
        lines.append(f"| [{cve}]({ADVISORY_URLS.get(cve, '#')}) | {CVSS_SCORE} | {patches} |")

    lines += ["", "## Findings", ""]

    for i, f in enumerate(report.findings, 1):
        version_str = str(f.php_version) if f.php_version else "not detected"
        status_str = (
            f.remote_status.value if f.remote_status else f.vuln_status.value
        )

        lines += [
            f"### [{i}] {f.target}",
            "",
            f"- **Timestamp:** {f.timestamp}",
            f"- **PHP Version:** {version_str}",
            f"- **Status:** `{status_str}`",
            f"- **Confidence:** {f.confidence.value}",
            f"- **CVEs:** {', '.join(f.cves)}",
            "",
        ]

        if f.checks_performed:
            lines.append(f"**Checks performed:** {', '.join(f.checks_performed)}")
            lines.append("")

        if f.evidence:
            lines.append("**Evidence:**")
            for e in f.evidence:
                lines.append(f"- {e}")
            lines.append("")

        if f.notes:
            lines.append("**Notes:**")
            for n in f.notes:
                lines.append(f"- ⚠️ {n}")
            lines.append("")

        if f.recommendations:
            lines.append("**Recommendations:**")
            for r in f.recommendations:
                lines.append(f"- {r}")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines += [
        "## References",
        "",
        f"- [CVE-2026-109618 Advisory]({ADVISORY_URLS['CVE-2026-109618']})",
        f"- [CVE-2026-109619 Advisory]({ADVISORY_URLS['CVE-2026-109619']})",
        "- [PHP Security Advisories](https://www.php.net/security)",
        "- [PHP Downloads](https://www.php.net/downloads)",
    ]

    text = "\n".join(lines)
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
    return text
