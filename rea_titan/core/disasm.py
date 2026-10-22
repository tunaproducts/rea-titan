"""Ultra-fast binary disassembly engine powered by Capstone."""

from pathlib import Path
from typing import Any, Dict, List, Optional
import capstone


ARCH_MAP = {
    "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
    "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
    "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
    "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    "mips": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
    "riscv": (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64),
}


class FastDisassembler:
    """Disassembles binary offsets or raw opcodes in microseconds."""

    def __init__(self, arch: str = "x86_64"):
        cs_arch, cs_mode = ARCH_MAP.get(arch.lower(), (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
        self.md = capstone.Cs(cs_arch, cs_mode)
        self.md.detail = True

    def disassemble_bytes(self, code_bytes: bytes, base_address: int = 0x1000, max_instructions: int = 50) -> List[Dict[str, Any]]:
        """Disassemble raw byte sequence."""
        instructions = []
        count = 0
        for insn in self.md.disasm(code_bytes, base_address):
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
                "size": insn.size,
            })
            count += 1
            if count >= max_instructions:
                break
        return instructions

    def disassemble_file_offset(self, filepath: str | Path, offset: int, length: int = 128, base_address: Optional[int] = None) -> List[Dict[str, Any]]:
        """Read and disassemble a slice of a binary file."""
        target = Path(filepath).resolve()
        with open(target, "rb") as f:
            f.seek(offset)
            data = f.read(length)
        addr = base_address if base_address is not None else offset
        return self.disassemble_bytes(data, base_address=addr)
