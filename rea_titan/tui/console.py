"""Rich visual console, banners, and cyberpunk styling for REA-TITAN."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax

console = Console()

BANNER = """[bold cyan]
██████╗ ███████╗ █████╗     ████████╗██╗████████╗ █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║
██████╔╝█████╗  ███████║       ██║   ██║   ██║   ███████║██╔██╗ ██║
██╔══██╗██╔══╝  ██╔══██║       ██║   ██║   ██║   ██╔══██║██║╚██╗██║
██║  ██║███████╗██║  ██║       ██║   ██║   ██║   ██║  ██║██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝       ╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold cyan][bold magenta]─── Next-Gen Reverse Engineering AI Suite & Ghidra Automation Core ───[/bold magenta]
"""


def print_banner():
    console.print(BANNER)


def print_triage_panel(triage: dict):
    table = Table(title="[bold yellow]Binary Triage Summary[/bold yellow]", border_style="cyan")
    table.add_column("Property", style="bold green", width=20)
    table.add_column("Value", style="white")

    table.add_row("Filename", str(triage.get("filename", "-")))
    table.add_row("Format", str(triage.get("format", "-")))
    table.add_row("File Size", str(triage.get("size_human", "-")))
    table.add_row("Machine / Arch", str(triage.get("machine", "-")))
    table.add_row("Bitness", f"{triage.get('bitness', '-')}-bit" if triage.get("bitness") else "-")
    table.add_row("Endianness", str(triage.get("endianness", "-")))
    table.add_row("Entry Point", str(triage.get("entry_point", "-")))

    syms = triage.get("symbols", {})
    if syms:
        table.add_row("Imported Symbols", str(len(syms.get("imports", []))))
        table.add_row("Exported Symbols", str(len(syms.get("exports", []))))

    console.print(table)


def print_mitigations_table(mit: dict):
    table = Table(title="[bold yellow]Security Mitigations (Checksec)[/bold yellow]", border_style="red")
    table.add_column("Mitigation", style="bold white")
    table.add_column("Status", style="bold")

    canary = mit.get("canary")
    table.add_row("Stack Canary", "[green]FOUND[/green]" if canary else "[red]DISABLED[/red]")

    nx = mit.get("nx")
    table.add_row("NX / DEP", "[green]ENABLED[/green]" if nx else "[red]DISABLED (RWE stack)[/red]")

    pie = mit.get("pie", "-")
    pie_style = "green" if "enabled" in str(pie).lower() else "red"
    table.add_row("PIE / ASLR", f"[{pie_style}]{pie}[/{pie_style}]")

    relro = mit.get("relro", "-")
    relro_style = "green" if "full" in str(relro).lower() else "yellow" if "partial" in str(relro).lower() else "red"
    table.add_row("RELRO", f"[{relro_style}]{relro}[/{relro_style}]")

    stripped = mit.get("symbols_stripped")
    table.add_row("Symbols Stripped", "[yellow]YES[/yellow]" if stripped else "[green]NO (Symbols Present)[/green]")

    console.print(table)


def print_entropy_summary(entropy_data: dict):
    ent = entropy_data.get("overall_entropy", 0.0)
    is_packed = entropy_data.get("is_packed_or_encrypted", False)
    color = "red" if is_packed else "green"

    panel_text = Text()
    panel_text.append(f"Overall Shannon Entropy: {ent} / 8.0\n", style=f"bold {color}")
    panel_text.append(f"Classification: {'PACKED OR ENCRYPTED' if is_packed else 'STANDARD BINARY'}\n", style=f"bold {color}")
    panel_text.append(f"High Entropy Blocks: {entropy_data.get('high_entropy_count', 0)}\n", style="white")
    panel_text.append(f"Recommendation: {entropy_data.get('recommendation', '')}", style="italic cyan")

    console.print(Panel(panel_text, title="[bold yellow]Entropy Scan[/bold yellow]", border_style=color))


def print_decompiled_code(func_name: str, code: str):
    syntax = Syntax(code, "c", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title=f"[bold green]Decompiled: {func_name}[/bold green]", border_style="green"))
