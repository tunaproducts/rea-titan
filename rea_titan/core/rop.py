"""Fast ROP (Return-Oriented Programming) gadget scanner for security auditing."""

from pathlib import Path
from typing import Any, Dict, List
import capstone


class ROPGadgetScanner:
    """Finds common ROP gadgets in binary executable code for mitigation testing."""

    def __init__(self, filepath: str | Path):
        self.path = Path(filepath).resolve()
        with open(self.path, "rb") as f:
            self.data = f.read()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def scan_gadgets(self, max_gadgets: int = 25) -> Dict[str, Any]:
        """Search for RET-terminated sequences in the binary."""
        gadgets = []
        ret_opcode = b"\xc3"  # x86_64 RET

        idx = 0
        while True:
            pos = self.data.find(ret_opcode, idx)
            if pos == -1 or len(gadgets) >= max_gadgets:
                break

            # Backtrack up to 10 bytes before RET
            start = max(0, pos - 8)
            chunk = self.data[start : pos + 1]

            # Try disassembling from different offsets
            for offset_delta in range(len(chunk) - 1):
                sub_chunk = chunk[offset_delta:]
                insns = list(self.md.disasm(sub_chunk, start + offset_delta))
                if insns and insns[-1].mnemonic == "ret" and len(insns) <= 4:
                    gadget_text = " ; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns)
                    addr = hex(start + offset_delta)
                    if not any(g["gadget"] == gadget_text for g in gadgets):
                        # Filter to most impactful gadgets
                        if any(k in gadget_text for k in ["pop rdi", "pop rsi", "pop rdx", "pop rax", "syscall", "ret"]):
                            gadgets.append({
                                "address": addr,
                                "gadget": gadget_text,
                                "length": len(sub_chunk),
                            })
                            if len(gadgets) >= max_gadgets:
                                break

            idx = pos + 1

        return {
            "total_gadgets_found": len(gadgets),
            "gadgets": gadgets,
            "defensive_note": (
                "Gadgets can be mitigated using Control Flow Integrity (CFI) or Intel CET shadow stacks."
            ),
        }
