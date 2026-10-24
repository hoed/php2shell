"""CLI for PHP2Shell Sentinel.

Commands
--------
  version-check  Show CVE patch matrix and patched PHP versions
  audit-local    Audit all local PHP installations
  assess         Conservative remote HTTP assessment (authorised targets only)
  report         Re-render a saved JSON report
  lab-check      Verify Docker lab isolation
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from .._version_check import check_python_version
from ..core.lab_check import check_lab
from ..core.local_audit import run_local_audit
from ..core.models import CVE_IDS, CVSS_SCORE, EOL_BRANCHES, PATCHED_VERSIONS, AssessmentReport
from ..core.remote_assess import MAX_TARGETS, assess_remote_batch
from ..reporting.renderer import (
    print_report_terminal,
    render_json,
    render_markdown,
)

app = typer.Typer(
    name="php2shell-sentinel",
    help="PHP Runtime Vulnerability Assessment Toolkit — CVE-2026-109618 / CVE-2026-109619",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Output format enum
# ---------------------------------------------------------------------------


class OutputFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    markdown = "markdown"
    all = "all"


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------

_format_option = Annotated[
    OutputFormat,
    typer.Option("--format", "-f", help="Output format.", show_default=True),
]

_output_option = Annotated[
    str | None,
    typer.Option("--output", "-o", help="Write report to this file path (omit for stdout)."),
]


# ---------------------------------------------------------------------------
# version-check
# ---------------------------------------------------------------------------


@app.command("version-check")
def version_check() -> None:
    """Display the PHP2Shell CVE patch matrix."""
    console.print("\n[bold cyan]PHP2Shell Sentinel — Patch Matrix[/]\n")
    console.print(f"[dim]CVEs tracked:[/] {', '.join(CVE_IDS)}")
    console.print(f"[dim]CVSS v4.0 score:[/] {CVSS_SCORE}")
    console.print("[dim]Patch date:[/] 2026-10-21\n")

    from rich import box as rbox
    from rich.table import Table

    table = Table(box=rbox.ROUNDED, show_lines=True)
    table.add_column("PHP Branch", style="bold")
    table.add_column("Patched Version", style="green")
    table.add_column("Status")

    for branch, patched in sorted(PATCHED_VERSIONS.items()):
        table.add_row(branch, patched, "[green]✓ Patch available[/]")

    for branch in sorted(EOL_BRANCHES, reverse=True):
        table.add_row(branch, "N/A", "[yellow]⚠ EOL — no official patch[/]")

    console.print(table)
    console.print()
    console.print("[dim]References:[/]")
    console.print("  • https://github.com/advisories/GHSA-w8hw-w9fx-j79w  (CVE-2026-109618)")
    console.print("  • https://github.com/advisories/GHSA-6wmf-4rv5-p3rp  (CVE-2026-109619)")
    console.print()


# ---------------------------------------------------------------------------
# audit-local
# ---------------------------------------------------------------------------


@app.command("audit-local")
def audit_local(
    format: _format_option = OutputFormat.terminal,
    output: _output_option = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Extra detail.")] = False,
) -> None:
    """Audit all local PHP installations for CVE-2026-109618 / CVE-2026-109619."""
    console.print("[dim]Scanning local PHP installations…[/]\n")
    report = run_local_audit(verbose=verbose)
    _output_report(report, format, output)
    _exit_code(report)


# ---------------------------------------------------------------------------
# assess (remote)
# ---------------------------------------------------------------------------


@app.command("assess")
def assess(
    target: Annotated[
        str | None,
        typer.Option("--target", "-t", help="Single authorised target URL."),
    ] = None,
    target_file: Annotated[
        Path | None,
        typer.Option("--target-file", help="File with one target URL per line."),
    ] = None,
    allowlist: Annotated[
        list[str] | None,
        typer.Option(
            "--allowlist",
            help="Explicitly authorised host(s). Repeat for multiple. "
            "Targets NOT in this list are skipped.",
        ),
    ] = None,
    allowlist_file: Annotated[
        Path | None,
        typer.Option("--allowlist-file", help="File with one authorised host per line."),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="HTTP request timeout in seconds.", show_default=True),
    ] = 10.0,
    rate_delay: Annotated[
        float,
        typer.Option("--rate-delay", help="Delay between requests (seconds).", show_default=True),
    ] = 1.0,
    no_verify_tls: Annotated[
        bool,
        typer.Option("--no-verify-tls", help="Disable TLS certificate verification (lab only)."),
    ] = False,
    format: _format_option = OutputFormat.terminal,
    output: _output_option = None,
) -> None:
    """
    Conservative remote HTTP assessment of authorised target(s).

    \b
    IMPORTANT:
      Only assess systems you are explicitly authorised to test.
      This command reads HTTP headers only — no exploit payloads are sent.
    """
    # Collect targets
    targets: list[str] = []
    if target:
        targets.append(target)
    if target_file:
        if not target_file.exists():
            err_console.print(f"[red]Target file not found: {target_file}[/]")
            raise typer.Exit(1)
        targets.extend(
            line.strip() for line in target_file.read_text().splitlines() if line.strip()
        )
    if not targets:
        err_console.print("[red]Provide --target or --target-file.[/]")
        raise typer.Exit(1)

    if len(targets) > MAX_TARGETS:
        err_console.print(
            f"[red]Too many targets ({len(targets)}). Maximum per session: {MAX_TARGETS}.[/]"
        )
        raise typer.Exit(1)

    # Collect allowlist
    allowed: list[str] = list(allowlist) if allowlist else []
    if allowlist_file:
        if not allowlist_file.exists():
            err_console.print(f"[red]Allowlist file not found: {allowlist_file}[/]")
            raise typer.Exit(1)
        allowed.extend(
            line.strip() for line in allowlist_file.read_text().splitlines() if line.strip()
        )
    if not allowed:
        # Auto-add the targets themselves (convenience for single-target use)
        allowed = list(targets)
        console.print(
            "[yellow]⚠  No --allowlist provided. "
            "Auto-allowing the supplied target(s). "
            "Confirm you are authorised to assess these systems.[/]\n"
        )

    if no_verify_tls:
        console.print(
            "[yellow]⚠  TLS verification disabled. Use in isolated lab environments only.[/]\n"
        )

    console.print(f"[dim]Assessing {len(targets)} target(s)…[/]\n")
    report = assess_remote_batch(
        targets=targets,
        allowlist=allowed,
        timeout=timeout,
        rate_limit_delay=rate_delay,
        verify_tls=not no_verify_tls,
    )
    _output_report(report, format, output)
    _exit_code(report)


# ---------------------------------------------------------------------------
# report (re-render saved JSON)
# ---------------------------------------------------------------------------


@app.command("report")
def report_cmd(
    input_file: Annotated[Path, typer.Argument(help="Path to a saved JSON report.")],
    format: _format_option = OutputFormat.terminal,
    output: _output_option = None,
) -> None:
    """Re-render a previously saved JSON report in another format."""
    import json

    if not input_file.exists():
        err_console.print(f"[red]File not found: {input_file}[/]")
        raise typer.Exit(1)

    try:
        raw = json.loads(input_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        err_console.print(f"[red]Invalid JSON: {exc}[/]")
        raise typer.Exit(1) from exc

    from ..core.models import (
        Confidence,
        RemoteStatus,
        VulnerabilityFinding,
        VulnStatus,
    )

    findings: list[VulnerabilityFinding] = []
    for fd in raw.get("findings", []):
        php_v = None
        if fd.get("php_version"):
            from ..core.version_parser import parse_php_version

            php_v = parse_php_version(fd["php_version"], source=fd.get("php_version_source", ""))
        findings.append(
            VulnerabilityFinding(
                target=fd["target"],
                timestamp=fd.get("timestamp", ""),
                php_version=php_v,
                vuln_status=VulnStatus(fd.get("vuln_status", "UNKNOWN")),
                remote_status=(
                    RemoteStatus(fd["remote_status"]) if fd.get("remote_status") else None
                ),
                confidence=Confidence(fd.get("confidence", "LOW")),
                evidence=fd.get("evidence", []),
                notes=fd.get("notes", []),
                recommendations=fd.get("recommendations", []),
                checks_performed=fd.get("checks_performed", []),
            )
        )

    report = AssessmentReport(
        scope=raw.get("scope", ""),
        generated_at=raw.get("generated_at", ""),
        toolkit_version=raw.get("toolkit_version", ""),
        findings=findings,
    )
    _output_report(report, format, output)


# ---------------------------------------------------------------------------
# lab-check
# ---------------------------------------------------------------------------


@app.command("lab-check")
def lab_check(
    compose_file: Annotated[
        str | None,
        typer.Option("--compose-file", help="Path to docker-compose.yml."),
    ] = "lab/docker-compose.yml",
) -> None:
    """Verify Docker lab isolation and container status."""
    console.print("[dim]Checking lab environment…[/]\n")
    status = check_lab(compose_file=compose_file)

    if status.docker_available:
        console.print("[green]✓[/] Docker is available.")
    else:
        console.print("[red]✗[/] Docker not found.")

    if status.compose_available:
        console.print("[green]✓[/] Docker Compose is available.")
    else:
        console.print("[yellow]⚠[/] Docker Compose not found.")

    if status.containers:
        console.print(f"\n[bold]Running lab containers ({len(status.containers)}):[/]")
        for c in status.containers:
            console.print(
                f"  • [bold]{c['name']}[/]  image={c['image']}  "
                f"status={c['status']}  ports={c['ports'] or 'none'}"
            )
    else:
        console.print("\n[dim]No lab containers currently running.[/]")

    if status.warnings:
        console.print("\n[bold yellow]Warnings:[/]")
        for w in status.warnings:
            console.print(f"  ⚠  {w}")

    if status.errors:
        console.print("\n[bold red]Errors:[/]")
        for e in status.errors:
            console.print(f"  ✗  {e}")

    if status.recommendations:
        console.print("\n[bold green]Next steps:[/]")
        for r in status.recommendations:
            console.print(f"  → {r}")

    console.print()
    if status.healthy:
        console.print("[green]Lab environment looks healthy.[/]")
    else:
        console.print("[red]Lab environment has issues. Review errors above.[/]")
        raise typer.Exit(2)


# ---------------------------------------------------------------------------
# fingerprint (standalone deep probe)
# ---------------------------------------------------------------------------


@app.command("fingerprint")
def fingerprint_cmd(
    target: Annotated[str, typer.Argument(help="Target URL to fingerprint.")],
    allowlist: Annotated[
        list[str] | None,
        typer.Option("--allowlist", help="Authorised host(s). Defaults to target host."),
    ] = None,
    no_verify_tls: Annotated[
        bool,
        typer.Option("--no-verify-tls", help="Disable TLS verification (lab only)."),
    ] = False,
    timeout: Annotated[float, typer.Option("--timeout", show_default=True)] = 10.0,
) -> None:
    """
    Deep passive fingerprinting: header correlation, error-page analysis,
    cookie probing, and response-timing — no exploit payloads sent.

    \b
    Only run against systems you are authorised to assess.
    """
    from ..core.fingerprint import fingerprint
    from ..core.remote_assess import validate_scope

    allowed = list(allowlist) if allowlist else []
    if not allowed:
        from urllib.parse import urlparse

        host = urlparse(target).hostname or target
        allowed = [host]
        console.print(
            f"[yellow]⚠  Auto-allowing {host!r}. "
            "Confirm you are authorised to assess this host.[/]\n"
        )

    if not validate_scope(target, allowed):
        err_console.print(
            f"[red]Target {target!r} is not in the allowlist. Add it with --allowlist.[/]"
        )
        raise typer.Exit(1)

    console.print(f"[dim]Running deep fingerprinting on {target} …[/]\n")

    result = fingerprint(target, timeout=timeout, verify_tls=not no_verify_tls)

    status_colour = "green" if result.php_detected else "dim"
    console.print(f"[bold]Target:[/] {result.target}")
    console.print(f"[bold]PHP detected:[/] [{status_colour}]{result.php_detected}[/]")
    console.print(f"[bold]Version hint:[/] {result.version_hint or 'not determined'}")
    console.print(f"[bold]Confidence:[/] {result.confidence.value}")
    console.print(f"[bold]Techniques used:[/] {', '.join(result.techniques_used) or 'none'}")

    if result.evidence:
        console.print("\n[bold]Evidence:[/]")
        for e in result.evidence:
            console.print(f"  • {e}")

    if result.warnings:
        console.print("\n[bold yellow]Warnings:[/]")
        for w in result.warnings:
            console.print(f"  ⚠  {w}")

    console.print()
    if result.php_detected:
        console.print(
            "[yellow]PHP presence confirmed — run full assess for vulnerability status.[/]"
        )
    else:
        console.print("[dim]No conclusive PHP evidence found.[/]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _output_report(
    report: AssessmentReport,
    format: OutputFormat,
    output: str | None,
) -> None:
    if format in (OutputFormat.terminal, OutputFormat.all):
        print_report_terminal(report)

    if format in (OutputFormat.json, OutputFormat.all):
        path = (
            output
            if format == OutputFormat.json
            else (output.replace(".md", ".json") if output else None)
        )
        json_text = render_json(report, output_path=path)
        if format == OutputFormat.json and not output:
            print(json_text)

    if format in (OutputFormat.markdown, OutputFormat.all):
        path = (
            output
            if format == OutputFormat.markdown
            else (output.replace(".json", ".md") if output else None)
        )
        md_text = render_markdown(report, output_path=path)
        if format == OutputFormat.markdown and not output:
            print(md_text)

    if output:
        console.print(f"[dim]Report written to:[/] {output}")


def _exit_code(report: AssessmentReport) -> None:
    """Exit 1 if any finding is VULNERABLE or POTENTIALLY_AFFECTED."""
    for f in report.findings:
        if f.vuln_status == f.vuln_status.VULNERABLE:
            raise typer.Exit(1)
        if f.remote_status and f.remote_status.value == "POTENTIALLY_AFFECTED":
            raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:  # noqa: D401
    check_python_version()
    app()


if __name__ == "__main__":
    main()
