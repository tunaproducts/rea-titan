"""Interactive AI Reverse Engineering Copilot & Guidance Assistant.

Works 100% offline with heuristic expert knowledge, and can optionally connect to live LLM APIs.
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from rea_titan.core.binary import BinaryTriage
from rea_titan.core.entropy import EntropyScanner
from rea_titan.core.license_audit import LicenseAndAntiTamperAuditor
from rea_titan.core.mitigations import MitigationsChecker
from rea_titan.core.strings import StringMiner
from rea_titan.ghidra.headless import GhidraHeadlessEngine

console = Console()


class ReverseEngineeringCopilot:
    """Interactive AI Assistant guiding reverse engineers through binary analysis."""

    def __init__(self, filepath: str | Path):
        self.path = Path(filepath).resolve()
        if not self.path.is_file():
            raise FileNotFoundError(f"Binary file not found: {self.path}")

        console.print(f"[bold cyan][AI COPILOT][/bold cyan] Ingesting binary knowledge for: [bold green]{self.path.name}[/bold green]...")

        # Pre-flight inspection
        self.triage = BinaryTriage(self.path).full_triage()
        self.entropy = EntropyScanner(self.path).scan()
        self.mitigations = MitigationsChecker(self.path).analyze()
        self.strings = StringMiner(self.path, min_length=5).mine_secrets_and_endpoints()
        self.license_audit = LicenseAndAntiTamperAuditor(self.path).full_audit()
        self.decompiled_cache: Dict[str, Any] = {}

    def get_quick_briefing(self) -> str:
        """Generate high-level tactical guidance."""
        fmt = self.triage.get("format", "Unknown")
        arch = self.triage.get("machine", "Unknown")
        is_packed = self.entropy.get("is_packed_or_encrypted", False)
        anti_dbg = self.license_audit["anti_debugging"]["mechanisms"]
        key_check = self.license_audit["key_verification"]

        briefing = f"""[bold yellow]Target:[/bold yellow] {self.path.name} ({fmt} - {arch})
[bold yellow]Entropy:[/bold yellow] {self.entropy.get('overall_entropy')}/8.0 ({'Packed/Encrypted' if is_packed else 'Standard Code'})
[bold yellow]Key Verification:[/bold yellow] {key_check['validation_architecture']}
[bold yellow]Anti-Debugging:[/bold yellow] {len(anti_dbg)} mechanism(s) detected.
"""
        return briefing

    def answer_query(self, query: str) -> str:
        """Context-aware heuristic response engine."""
        q = query.lower().strip()

        if "key" in q or "license" in q or "serial" in q or "anahtar" in q or "lisans" in q:
            kv = self.license_audit["key_verification"]
            res = "[bold green]=== Key Validation & Authentication Architecture ===[/bold green]\n"
            res += f"• Validation Architecture: {kv['validation_architecture']}\n"
            if kv["validation_indicators"]:
                res += f"• Detected Keywords: {', '.join(kv['validation_indicators'])}\n"
            if kv["comparison_apis_used"]:
                res += f"• Comparison APIs: {', '.join(kv['comparison_apis_used'])}\n"
            if kv["timing_attack_vulnerability"]["vulnerable"]:
                res += f"• [bold red]Vulnerability Found:[/bold red] {kv['timing_attack_vulnerability']['reason']}\n"
                res += f"• Recommendation: {kv['timing_attack_vulnerability']['remediation']}\n"
            res += "\n[cyan]Tip: Use 'decompile <func_name>' to view the exact validation logic in C![/cyan]"
            return res

        elif "anti" in q or "debug" in q or "ptrace" in q or "bypass" in q:
            ad = self.license_audit["anti_debugging"]
            if not ad["mechanisms"]:
                return "[bold green]Good news:[/bold green] No active anti-debugging or ptrace tricks detected in static symbols."
            res = "[bold red]=== Anti-Debugging Mechanisms & Bypass Strategies ===[/bold red]\n"
            for m in ad["mechanisms"]:
                res += f"• [bold yellow]{m['api']}[/bold yellow] ({m['platform']}): {m['technique']}\n"
                res += f"  ↳ [green]Bypass:[/green] {m['bypass_strategy']}\n"
            return res

        elif "pack" in q or "crypt" in q or "entrop" in q or "şifre" in q:
            e = self.entropy
            res = f"[bold yellow]Entropy Score:[/bold yellow] {e['overall_entropy']} / 8.0\n"
            res += f"Status: {'High likelihood of packer (UPX, VMProtect, custom XOR).' if e['is_packed_or_encrypted'] else 'Not packed. Direct static disassembly is viable.'}\n"
            res += f"Advice: {e['recommendation']}"
            return res

        elif "string" in q or "url" in q or "ip" in q or "token" in q:
            s = self.strings
            res = f"[bold green]Total Extracted Strings:[/bold green] {s['total_strings_count']}\n"
            if s["urls"]:
                res += f"• Discovered URLs: {', '.join(s['urls'][:5])}\n"
            if s["ips"]:
                res += f"• Discovered IPs: {', '.join(s['ips'][:5])}\n"
            if s["tokens"]:
                res += f"• Potential Tokens: {', '.join(s['tokens'])}\n"
            if s["shell_commands_and_exec"]:
                res += f"• Executables Called: {', '.join(s['shell_commands_and_exec'][:5])}\n"
            return res

        elif "patch" in q or "yamala" in q or "bypass" in q:
            return (
                "[bold cyan]=== Ethical Binary Patching Guidance ===[/bold cyan]\n"
                "1. Locate the conditional jump after the verification function (e.g. JZ 0x74 or JNZ 0x75).\n"
                "2. To bypass in authorized defensive evaluation:\n"
                "   • Invert jump: Change 74 xx (JZ) to 75 xx (JNZ).\n"
                "   • Unconditional: Change to EB xx (JMP) or 90 90 (NOP).\n"
                "3. Verify with dynamic tracing (using './bin/rea-titan frida')."
            )

        elif q.startswith("decompile") or q.startswith("deşifre"):
            parts = query.split()
            func_name = parts[1] if len(parts) > 1 else "main"
            engine = GhidraHeadlessEngine()
            console.print(f"[cyan]Invoking Ghidra headless decompiler on '{func_name}'...[/cyan]")
            decomp = engine.decompile_binary(self.path)
            if decomp.get("status") == "success":
                funcs = decomp["data"].get("functions", [])
                for f in funcs:
                    if func_name.lower() in f["name"].lower():
                        return f"[bold green]Decompiled: {f['name']}[/bold green]\n```c\n{f['decompiled_code']}\n```"
                return f"[yellow]Function '{func_name}' not found. Try 'main'.[/yellow]"
            return f"[red]Decompilation failed: {decomp.get('message')}[/red]"

        return (
            "[bold cyan]AI Copilot Advice:[/bold cyan]\n"
            "You can ask me about:\n"
            " • 'keys' or 'license' -> How the binary validates serials & timing leaks\n"
            " • 'antidebug' -> How to bypass detected anti-debugging/ptrace hooks\n"
            " • 'entropy' -> Check if binary is encrypted/packed\n"
            " • 'strings' -> View extracted secrets and endpoints\n"
            " • 'decompile <func>' -> Ask Ghidra to decompile any function\n"
            " • 'patch' -> Advice on conditional jump modification"
        )

    def interactive_session(self):
        """Run interactive RE guidance loop."""
        console.print(Panel(self.get_quick_briefing(), title="[bold magenta]⚡ REA-TITAN AI COPILOT[/bold magenta]", border_style="magenta"))
        console.print("[italic cyan]Type your question or target goal (e.g., 'keys', 'antidebug', 'decompile verify_license', 'exit').[/italic cyan]\n")

        while True:
            try:
                user_input = Prompt.ask("[bold green]Titan-Copilot[/bold green] [bold white]>[/bold white]")
                if not user_input or user_input.strip().lower() in ("exit", "quit", "q"):
                    console.print("[bold yellow]Exiting AI Copilot session. Happy reversing![/bold yellow]")
                    break
                response = self.answer_query(user_input)
                console.print(f"\n{response}\n")
            except (KeyboardInterrupt, EOFError):
                break
