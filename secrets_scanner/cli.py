import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from .scanner import Finding, ScanResult, scan
from .patterns import SEVERITY_ORDER

console = Console()
err_console = Console(stderr=True)

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim white",
}

def _severity_badge(severity):
    color = SEVERITY_COLORS.get(severity, "white")
    t = Text()
    t.append(f" {severity.upper()} ", style=f"{color} on grey19")
    return t


def _print_finding(f, show_context):
    rel = f.file
    try:
        rel = str(Path(f.file).relative_to(Path.cwd()))
    except ValueError:
        pass

    header = Text()
    header.append(f"{rel}", style="bold cyan")
    header.append(f":{f.line_number}", style="dim")
    header.append("  ")
    header.append_text(_severity_badge(f.pattern.severity))
    header.append(f"  {f.pattern.name}", style="bold")

    console.print(header)
    console.print(f"  [dim]{f.pattern.description}[/dim]")
    console.print(f"  [dim]Secret (masked):[/dim] [bold yellow]{f.match}[/bold yellow]")

    if show_context:
        lines_to_show = []
        start_ln = f.line_number - len(f.context_before)

        for i, ctx in enumerate(f.context_before):
            lines_to_show.append((start_ln + i, ctx, False))
        lines_to_show.append((f.line_number, f.line, True))
        for i, ctx in enumerate(f.context_after):
            lines_to_show.append((f.line_number + 1 + i, ctx, False))

        for ln, text, is_match in lines_to_show:
            prefix = f"  [dim]{ln:>5}[/dim] "
            if is_match:
                console.print(f"{prefix}[bold red]>[/bold red] {text}")
            else:
                console.print(f"{prefix}  [dim]{text}[/dim]")

    console.print()


def _print_table(result):
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
        border_style="dim",
    )
    table.add_column("Severity", width=10)
    table.add_column("Pattern", style="bold")
    table.add_column("File", style="cyan")
    table.add_column("Line", justify="right", width=6)
    table.add_column("Secret (masked)", style="yellow")

    for f in result.findings:
        rel = f.file
        try:
            rel = str(Path(f.file).relative_to(Path.cwd()))
        except ValueError:
            pass
        color = SEVERITY_COLORS.get(f.pattern.severity, "white")
        table.add_row(
            Text(f.pattern.severity.upper(), style=color),
            f.pattern.name,
            rel,
            str(f.line_number),
            f.match,
        )

    console.print(table)


def _print_summary(result, path):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in result.findings:
        counts[f.pattern.severity] = counts.get(f.pattern.severity, 0) + 1

    total = len(result.findings)

    summary = Text()
    summary.append(f"\nScanned ", style="dim")
    summary.append(f"{result.files_scanned}", style="bold")
    summary.append(f" files in ", style="dim")
    summary.append(f"{path}\n", style="bold")

    if result.files_skipped:
        summary.append(f"Skipped {result.files_skipped} binary/oversized files\n", style="dim")

    if total == 0:
        summary.append("\nNo secrets found.", style="bold green")
    else:
        summary.append(f"\nFound {total} potential secret(s):\n", style="bold")
        for sev in ("critical", "high", "medium", "low"):
            if counts[sev]:
                color = SEVERITY_COLORS[sev]
                summary.append(f"  {counts[sev]:>3} {sev}\n", style=color)

    if result.errors:
        summary.append(f"\n{len(result.errors)} file(s) could not be read\n", style="yellow")

    console.print(Panel(summary, title="[bold]Scan Summary[/bold]", border_style="dim"))


def _output_json(result):
    data = {
        "summary": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "total_findings": len(result.findings),
            "by_severity": {},
        },
        "findings": [],
    }
    for f in result.findings:
        rel = f.file
        try:
            rel = str(Path(f.file).relative_to(Path.cwd()))
        except ValueError:
            pass
        data["findings"].append(
            {
                "file": rel,
                "line": f.line_number,
                "severity": f.pattern.severity,
                "pattern": f.pattern.name,
                "description": f.pattern.description,
                "secret_masked": f.match,
                "line_content": f.line,
            }
        )
        sev = f.pattern.severity
        data["summary"]["by_severity"][sev] = data["summary"]["by_severity"].get(sev, 0) + 1

    click.echo(json.dumps(data, indent=2))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--severity", "-s",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default="low",
    show_default=True,
    help="Minimum severity level to report.",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["pretty", "table", "json"], case_sensitive=False),
    default="pretty",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--no-context", is_flag=True, default=False,
    help="Hide surrounding code context lines.",
)
@click.option(
    "--no-gitignore", is_flag=True, default=False,
    help="Do not respect .gitignore rules.",
)
@click.option(
    "--include-ext", "include_exts",
    multiple=True, metavar="EXT",
    help="Only scan files with these extensions (e.g. .py .js). Repeatable.",
)
@click.option(
    "--exclude-ext", "exclude_exts",
    multiple=True, metavar="EXT",
    help="Skip files with these extensions. Repeatable.",
)
@click.option(
    "--exit-zero", is_flag=True, default=False,
    help="Always exit with code 0, even when secrets are found.",
)
def cli(path, severity, output_format, no_context, no_gitignore, include_exts, exclude_exts, exit_zero):
    """Scan a codebase for exposed secrets, API keys, and credentials.

    PATH defaults to the current directory.

    Examples:

      secrets-scanner .

      secrets-scanner ./src --severity high --format json

      secrets-scanner . --include-ext .py --include-ext .js

      secrets-scanner . --format table --no-context
    """
    # Normalize extensions to make sure they start with a dot
    inc = None
    if len(include_exts) > 0:
        inc = set()
        for e in include_exts:
            if not e.startswith("."):
                e = "." + e
            inc.add(e)

    exc = set()
    for e in exclude_exts:
        if not e.startswith("."):
            e = "." + e
        exc.add(e)

    if output_format != "json":
        console.print(f"\n[bold]Secrets Scanner[/bold] [dim]— scanning [cyan]{path}[/cyan][/dim]\n")

    result = scan(
        path=path,
        include_exts=inc,
        exclude_exts=exc,
        min_severity=severity,
        respect_gitignore=not no_gitignore,
        context_lines=0 if no_context else 2,
    )

    if output_format == "json":
        _output_json(result)
    elif output_format == "table":
        if len(result.findings) > 0:
            _print_table(result)
        _print_summary(result, path)
    else:  # pretty
        for finding in result.findings:
            _print_finding(finding, show_context=not no_context)
        _print_summary(result, path)

    if len(result.errors) > 0 and output_format != "json":
        err_console.print("\n[yellow]Errors:[/yellow]")
        for fpath, reason in result.errors:
            err_console.print(f"  [dim]{fpath}:[/dim] {reason}")

    if not exit_zero and len(result.findings) > 0:
        sys.exit(1)


def main():
    cli()
