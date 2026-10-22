"""Binary mitigations and checksec analyzer."""

import subprocess
from pathlib import Path
from typing import Any, Dict


class MitigationsChecker:
    """Checks binary security mitigations (NX, PIE, Canary, RELRO)."""

    def __init__(self, filepath: str | Path):
        self.path = Path(filepath).resolve()

    def check_elf_mitigations(self) -> Dict[str, Any]:
        """Analyze ELF binary mitigations using readelf."""
        mitigations = {
            "canary": False,
            "nx": True,
            "pie": "No PIE",
            "relro": "No RELRO",
            "fortify": False,
            "symbols_stripped": True,
        }

        try:
            # Check program headers for GNU_STACK (NX)
            p_hdr = subprocess.run(
                ["readelf", "-l", str(self.path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in p_hdr.stdout.splitlines():
                if "GNU_STACK" in line:
                    mitigations["nx"] = "RWE" not in line
                if "GNU_RELRO" in line:
                    mitigations["relro"] = "Partial RELRO"

            # Check dynamic section for BIND_NOW (Full RELRO)
            p_dyn = subprocess.run(
                ["readelf", "-d", str(self.path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "BIND_NOW" in p_dyn.stdout:
                if mitigations["relro"] == "Partial RELRO":
                    mitigations["relro"] = "Full RELRO"

            # Check file type for PIE
            p_elf = subprocess.run(
                ["readelf", "-h", str(self.path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "DYN (Shared object file)" in p_elf.stdout or "DYN (Position-Independent Executable" in p_elf.stdout:
                mitigations["pie"] = "PIE enabled"
            elif "EXEC (Executable file)" in p_elf.stdout:
                mitigations["pie"] = "No PIE"

            # Check symbols for stack canary and fortify
            p_sym = subprocess.run(
                ["readelf", "-s", str(self.path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "__stack_chk_fail" in p_sym.stdout:
                mitigations["canary"] = True
            if "_chk" in p_sym.stdout:
                mitigations["fortify"] = True
            if ".symtab" in p_sym.stdout:
                mitigations["symbols_stripped"] = False

        except Exception:
            pass

        return mitigations

    def analyze(self) -> Dict[str, Any]:
        with open(self.path, "rb") as f:
            magic = f.read(4)

        if magic == b"\x7fELF":
            return self.check_elf_mitigations()
        elif magic[:2] == b"MZ":
            return {
                "format": "PE",
                "notes": "PE Mitigations (DEP/ASLR/CFG) typically determined via OptionalHeader DLLCharacteristics.",
            }
        return {"notes": "Mitigations check not applicable for raw/non-ELF binaries."}
