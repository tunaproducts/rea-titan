"""REA-TITAN Main CLI Entrypoint."""

import json
import sys
from pathlib import Path
import click

from rea_titan.bridge.dynamic_frida import FridaHookGenerator
from rea_titan.bridge.mcp_server import run_mcp_server
from rea_titan.bridge.pwntools_gen import PwntoolsHarnessGenerator
from rea_titan.config import ANALYZE_HEADLESS, GHIDRA_HOME
from rea_titan.core.assistant import ReverseEngineeringCopilot
from rea_titan.core.auditor import SecurityAuditor
from rea_titan.core.binary import BinaryTriage
from rea_titan.core.disasm import FastDisassembler
from rea_titan.core.entropy import EntropyScanner
from rea_titan.core.license_audit import LicenseAndAntiTamperAuditor
from rea_titan.core.mitigations import MitigationsChecker
from rea_titan.core.rop import ROPGadgetScanner
from rea_titan.core.signatures import SignatureDetector
from rea_titan.core.strings import StringMiner
from rea_titan.ghidra.headless import GhidraHeadlessEngine
from rea_titan.tui.console import (
    console,
    print_banner,
    print_decompiled_code,
    print_entropy_summary,
    print_mitigations_table,
    print_triage_panel,
)
from rea_titan.tui.hexview import render_hexdump


@click.group()
def cli():
    """REA-TITAN: Autonomous Reverse Engineering Suite & Ghidra Orchestrator."""
    pass


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
def triage(binary_path: str):
    """Perform quick binary triage and architecture detection."""
    print_banner()
    t = BinaryTriage(binary_path)
    res = t.full_triage()
    print_triage_panel(res)


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
def entropy(binary_path: str):
    """Analyze Shannon entropy and detect packing/encryption."""
    print_banner()
    scanner = EntropyScanner(binary_path)
    res = scanner.scan()
    print_entropy_summary(res)


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--min-length", default=5, help="Minimum string length")
def strings(binary_path: str, min_length: int):
    """Mine secrets, URLs, IPs, endpoints, and credentials."""
    print_banner()
    miner = StringMiner(binary_path, min_length=min_length)
    res = miner.mine_secrets_and_endpoints()

    console.print(f"[bold cyan]Total Extracted Strings:[/bold cyan] {res['total_strings_count']}")
    if res["urls"]:
        console.print("\n[bold green]Detected URLs:[/bold green]")
        for u in res["urls"]:
            console.print(f"  • {u}")
    if res["ips"]:
        console.print("\n[bold green]Detected IPs:[/bold green]")
        for ip in res["ips"]:
            console.print(f"  • {ip}")
    if res["tokens"]:
        console.print("\n[bold red]Detected Secrets/Tokens:[/bold red]")
        for tok in res["tokens"]:
            console.print(f"  • {tok}")
    if res["shell_commands_and_exec"]:
        console.print("\n[bold yellow]Command Executions / Shell References:[/bold yellow]")
        for c in res["shell_commands_and_exec"]:
            console.print(f"  • {c}")


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
def checksec(binary_path: str):
    """Inspect binary security mitigations (NX, PIE, Canary, RELRO)."""
    print_banner()
    checker = MitigationsChecker(binary_path)
    res = checker.analyze()
    print_mitigations_table(res)


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
def crypto(binary_path: str):
    """Scan for AES S-Boxes, SHA/MD5 constants, and known packers."""
    print_banner()
    detector = SignatureDetector(binary_path)
    res = detector.scan()

    if res["crypto_algorithms"]:
        console.print("[bold green]Cryptographic Constants Detected:[/bold green]")
        for c in res["crypto_algorithms"]:
            console.print(f"  [bold yellow]• {c['algorithm']}[/bold yellow] at offset [cyan]{c['offset']}[/cyan]")
    else:
        console.print("[cyan]No standard crypto algorithm constants found.[/cyan]")

    if res["packers_and_compilers"]:
        console.print("\n[bold magenta]Compilers & Packers Fingerprinted:[/bold magenta]")
        for p in res["packers_and_compilers"]:
            console.print(f"  • {p}")


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
def audit(binary_path: str):
    """Audit binary for dangerous C APIs, buffer overflows, and unsafe functions."""
    print_banner()
    auditor = SecurityAuditor(binary_path)
    res = auditor.audit_apis()

    console.print(f"[bold cyan]Security Posture Score:[/bold cyan] [bold green]{res['vulnerability_score']}[/bold green]")
    console.print(f"[bold cyan]Total Insecure API Findings:[/bold cyan] {res['findings_count']}\n")

    for f in res["findings"]:
        color = "bold red" if f["severity"] == "CRITICAL" else "yellow" if f["severity"] == "HIGH" else "cyan"
        console.print(f"[{color}][{f['severity']}][/{color}] [bold white]{f['function']}[/bold white]: {f['description']}")
        console.print(f"   [italic green]Remediation:[/italic green] {f['remediation']}\n")


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--offset", default="0x1000", help="Hex offset to disassemble from")
@click.option("--count", default=25, help="Number of instructions to disassemble")
def disasm(binary_path: str, offset: str, count: int):
    """Fast native disassembly with Capstone."""
    print_banner()
    off = int(offset, 16) if offset.startswith("0x") or offset.startswith("0X") else int(offset)
    d = FastDisassembler()
    insns = d.disassemble_file_offset(binary_path, offset=off, length=count * 8, base_address=off)

    console.print(f"[bold yellow]Disassembly at {offset}:[/bold yellow]")
    for i in insns[:count]:
        console.print(f"  [cyan]{i['address']}[/cyan]: [bold white]{i['mnemonic']:<8}[/bold white] {i['op_str']:<25} [italic dark_gray]; {i['bytes']}[/italic dark_gray]")


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
def keys(binary_path: str):
    """Audit license key verification flow, anti-tamper, and anti-debugging."""
    print_banner()
    auditor = LicenseAndAntiTamperAuditor(binary_path)
    res = auditor.full_audit()

    ad = res["anti_debugging"]
    kv = res["key_verification"]

    console.print(f"[bold cyan]Key Verification Architecture:[/bold cyan] [bold yellow]{kv['validation_architecture']}[/bold yellow]")
    if kv["validation_indicators"]:
        console.print(f"[bold green]Discovered Key Indicators:[/bold green] {', '.join(kv['validation_indicators'])}")
    if kv["comparison_apis_used"]:
        console.print(f"[bold green]Comparison APIs Used:[/bold green] {', '.join(kv['comparison_apis_used'])}")

    console.print(f"\n[bold cyan]Timing-Attack Leak Risk:[/bold cyan] {'[bold red]YES (Vulnerable)[/bold red]' if kv['timing_attack_vulnerability']['vulnerable'] else '[bold green]NO[/bold green]'}")
    console.print(f"[italic]{kv['timing_attack_vulnerability']['reason']}[/italic]")

    console.print(f"\n[bold cyan]Anti-Debugging Mechanisms:[/bold cyan] {ad['anti_debug_mechanisms_count']} detected.")
    for m in ad["mechanisms"]:
        console.print(f"  • [bold yellow]{m['api']}[/bold yellow] ({m['platform']}): {m['technique']}")
        console.print(f"    ↳ [italic green]Bypass:[/italic green] {m['bypass_strategy']}")


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
def copilot(binary_path: str):
    """Launch interactive AI Reverse Engineering Copilot session."""
    print_banner()
    c = ReverseEngineeringCopilot(binary_path)
    c.interactive_session()


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
def rop(binary_path: str):
    """Scan for ROP gadgets to evaluate exploitation mitigation resilience."""
    print_banner()
    scanner = ROPGadgetScanner(binary_path)
    res = scanner.scan_gadgets()

    console.print(f"[bold cyan]Discovered ROP Gadgets:[/bold cyan] {res['total_gadgets_found']}\n")
    for g in res["gadgets"]:
        console.print(f"  [cyan]{g['address']}[/cyan]: [bold green]{g['gadget']}[/bold green]")
    console.print(f"\n[italic cyan]{res['defensive_note']}[/italic cyan]")


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--offset", default="0x0", help="Hex offset to view")
@click.option("--length", default=256, help="Bytes length to dump")
def hex(binary_path: str, offset: str, length: int):
    """Display interactive colorized hexdump of target binary."""
    print_banner()
    off = int(offset, 16) if offset.startswith("0x") or offset.startswith("0X") else int(offset)
    table = render_hexdump(binary_path, offset=off, length=length)
    console.print(table)


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--func", default=None, help="Filter specific function name to print")
@click.option("--out", default=None, help="Save decompiled JSON output to file")
def decompile(binary_path: str, func: str | None, out: str | None):
    """Decompile binary using Ghidra Headless Analyzer into C pseudocode."""
    print_banner()
    if not ANALYZE_HEADLESS:
        console.print("[bold red]Ghidra analyzeHeadless was not found![/bold red]")
        console.print(f"Expected at: {GHIDRA_HOME}/support/analyzeHeadless")
        sys.exit(1)

    console.print(f"[bold green]Launching Ghidra headless decompiler on:[/bold green] {binary_path}")
    engine = GhidraHeadlessEngine()
    result = engine.decompile_binary(binary_path, output_json=out)

    if result.get("status") == "success":
        data = result["data"]
        functions = data.get("functions", [])
        console.print(f"[bold cyan]Successfully decompiled {len(functions)} functions![/bold cyan]")

        if func:
            matched = False
            for f in functions:
                if f["name"].lower() == func.lower() or func in f["name"]:
                    print_decompiled_code(f["name"], f["decompiled_code"])
                    matched = True
            if not matched:
                console.print(f"[yellow]Function '{func}' not found in decompiled output.[/yellow]")
        else:
            for f in functions[:3]:
                print_decompiled_code(f["name"], f["decompiled_code"])
            if len(functions) > 3:
                console.print(f"[italic cyan]...and {len(functions) - 3} more functions decompiled.[/italic cyan]")
    else:
        console.print(f"[bold red]Decompilation failed:[/bold red] {result.get('message')}")


@cli.command()
@click.argument("binary_name")
@click.argument("func_name_or_offset")
@click.option("--args-count", default=4, help="Number of arguments to inspect")
def frida(binary_name: str, func_name_or_offset: str, args_count: int):
    """Generate dynamic Frida instrumentation hook for target function."""
    print_banner()
    script = FridaHookGenerator.generate_function_hook(binary_name, func_name_or_offset, args_count)
    console.print("[bold green]Generated Frida Hook Script:[/bold green]")
    console.print(f"```javascript\n{script}\n```")


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
def pwn(binary_path: str):
    """Generate pwntools exploit harness template for the binary."""
    print_banner()
    checker = MitigationsChecker(binary_path)
    mit = checker.analyze()
    tmpl = PwntoolsHarnessGenerator.generate_template(binary_path, mit)
    console.print("[bold green]Generated Pwntools Harness:[/bold green]")
    console.print(f"```python\n{tmpl}\n```")


@cli.command()
def mcp():
    """Start REA-TITAN Model Context Protocol (MCP) server for AI Agents."""
    run_mcp_server()


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--report", default="titan_report.md", help="Output markdown report file")
def auto(binary_path: str, report: str):
    """Full-auto autonomous RE pipeline: Triage, Entropy, Strings, Checksec, Crypto, Audit & Decompilation."""
    print_banner()
    console.print(f"[bold green]Starting Full-Auto RE Pipeline on:[/bold green] {binary_path}")

    t = BinaryTriage(binary_path).full_triage()
    e = EntropyScanner(binary_path).scan()
    s = StringMiner(binary_path).mine_secrets_and_endpoints()
    m = MitigationsChecker(binary_path).analyze()
    c = SignatureDetector(binary_path).scan()
    a = SecurityAuditor(binary_path).audit_apis()

    print_triage_panel(t)
    print_mitigations_table(m)
    print_entropy_summary(e)

    # Generate Markdown Report
    md_content = f"""# REA-TITAN Autonomous Reverse Engineering Report
**Target Binary:** `{Path(binary_path).name}`  
**File Size:** {t.get('size_human')}  
**Format:** {t.get('format')} ({t.get('machine', 'Unknown')})  
**Entry Point:** `{t.get('entry_point', '-')}`  
**Security Posture Score:** {a.get('vulnerability_score')}  

---

## 1. Security Mitigations (Checksec)
- **Stack Canary:** {'Enabled' if m.get('canary') else 'Disabled'}
- **NX / DEP:** {'Enabled' if m.get('nx') else 'Disabled'}
- **PIE / ASLR:** {m.get('pie', '-')}
- **RELRO:** {m.get('relro', '-')}
- **Stripped:** {'Yes' if m.get('symbols_stripped') else 'No'}

## 2. Insecure API & Vulnerability Audit
- **Security Score:** {a.get('vulnerability_score')}
- **Findings Count:** {a.get('findings_count')}
"""
    for finding in a.get("findings", []):
        md_content += f"- **[{finding['severity']}] `{finding['function']}`**: {finding['description']}\n  - *Remediation:* {finding['remediation']}\n"

    md_content += f"""
## 3. Entropy & Packing Analysis
- **Overall Entropy:** {e.get('overall_entropy')} / 8.0
- **Is Packed / Encrypted:** {'YES' if e.get('is_packed_or_encrypted') else 'NO'}
- **Analysis:** {e.get('recommendation')}

## 4. Cryptographic Signatures & Packers
- **Crypto Constants Found:** {len(c.get('crypto_algorithms', []))}
"""
    for algo in c.get('crypto_algorithms', []):
        md_content += f"  - `{algo['algorithm']}` at offset `{algo['offset']}`\n"

    md_content += f"""
- **Compilers / Packers Detected:** {', '.join(c.get('packers_and_compilers', [])) or 'None'}

## 5. Interesting Strings & Endpoints
- **Total Strings:** {s.get('total_strings_count')}
- **Discovered URLs:** {len(s.get('urls', []))}
"""
    for u in s.get('urls', [])[:10]:
        md_content += f"  - {u}\n"

    md_content += f"""
- **Discovered IPs:** {len(s.get('ips', []))}
"""
    for ip in s.get('ips', [])[:10]:
        md_content += f"  - {ip}\n"

    Path(report).write_text(md_content, encoding="utf-8")
    console.print(f"\n[bold green]✓ Full autonomous report generated:[/bold green] [cyan]{report}[/cyan]")


if __name__ == "__main__":
    cli()
