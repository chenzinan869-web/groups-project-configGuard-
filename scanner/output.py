from rich.console import Console
from rich.table import Table
from rich import box

console = Console(force_terminal=True, force_jupyter=False)

def print_findings(findings):
    if not findings:
        console.print("\n[bold green]✅ No issues found![/bold green]\n")
        return

    for finding in findings:
        severity = finding["severity"]

        if severity == "HIGH":
            colour = "red"
            icon = "❌"
        elif severity == "MEDIUM":
            colour = "yellow"
            icon = "⚠️"
        else:
            colour = "green"
            icon = "ℹ️"

        console.print(f"\n{icon} [{colour}][{severity}][/{colour}] [bold]{finding['rule']}[/bold]")
        console.print(f"  [cyan]Service[/cyan]     : {finding['service']}")
        console.print(f"  [cyan]Description[/cyan] : {finding['description']}")
        console.print(f"  [cyan]Fix[/cyan]         : {finding['fix']}")

def print_summary(findings):
    high   = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low    = sum(1 for f in findings if f["severity"] == "LOW")

    table = Table(title="Scan Summary", box=box.ROUNDED)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="center")

    table.add_row("[red]HIGH[/red]", str(high))
    table.add_row("[yellow]MEDIUM[/yellow]", str(medium))
    table.add_row("[green]LOW[/green]", str(low))
    table.add_row("TOTAL", str(len(findings)))

    console.print("\n")
    console.print(table)
