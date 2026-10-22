"""Binary triage, header inspection, and format identification module."""

import os
import struct
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


class BinaryTriage:
    """Zero-dependency triage engine with optional external tool enrichment."""

    def __init__(self, filepath: str | Path):
        self.path = Path(filepath).resolve()
        if not self.path.is_file():
            raise FileNotFoundError(f"Binary file not found: {self.path}")
        self.size = self.path.stat().st_size
        self._raw_header = self._read_header(4096)

    def _read_header(self, length: int = 4096) -> bytes:
        with open(self.path, "rb") as f:
            return f.read(length)

    def detect_format(self) -> str:
        """Detect binary file format from magic bytes."""
        hdr = self._raw_header
        if len(hdr) >= 4 and hdr[:4] == b"\x7fELF":
            return "ELF"
        elif len(hdr) >= 2 and hdr[:2] == b"MZ":
            return "PE"
        elif len(hdr) >= 4 and hdr[:4] in (
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
        ):
            return "Mach-O"
        elif len(hdr) >= 4 and hdr[:4] == b"PK\x03\x04":
            return "ZIP/APK/JAR"
        elif len(hdr) >= 4 and hdr[:4] == b"\x1f\x8b\x08":
            return "GZIP"
        elif len(hdr) >= 4 and hdr[:4] == b"hsqs":
            return "SquashFS (Little-Endian)"
        elif len(hdr) >= 4 and hdr[:4] == b"sqsh":
            return "SquashFS (Big-Endian)"
        elif len(hdr) >= 4 and hdr[:4] == b"\x27\x05\x19\x56":
            return "U-Boot Image"
        elif len(hdr) >= 4 and hdr[:4] == b"\xca\xfe\xba\xbe":
            return "Java Class"
        elif len(hdr) >= 8 and hdr[:8] == b"\x89PNG\r\n\x1a\n":
            return "PNG Image"
        return "Raw Binary / Firmware"

    def inspect_elf(self) -> Dict[str, Any]:
        """Parse ELF basic headers using native struct unpacking."""
        hdr = self._raw_header
        if len(hdr) < 52 or hdr[:4] != b"\x7fELF":
            return {}

        ei_class = hdr[4]
        ei_data = hdr[5]
        is_64bit = ei_class == 2
        endian = "<" if ei_data == 1 else ">"

        e_type_val, e_machine_val = struct.unpack(f"{endian}HH", hdr[16:20])

        e_type_map = {
            1: "ET_REL (Relocatable object)",
            2: "ET_EXEC (Executable file)",
            3: "ET_DYN (Shared object / PIE)",
            4: "ET_CORE (Core dump)",
        }
        e_machine_map = {
            3: "x86 (Intel 80386)",
            62: "x86_64 (AMD x86-64)",
            40: "ARM (32-bit)",
            183: "AArch64 (ARM 64-bit)",
            8: "MIPS",
            243: "RISC-V",
            20: "PowerPC",
            21: "PowerPC 64-bit",
        }

        if is_64bit:
            e_entry = struct.unpack(f"{endian}Q", hdr[24:32])[0]
        else:
            e_entry = struct.unpack(f"{endian}I", hdr[24:28])[0]

        return {
            "format": "ELF",
            "bitness": 64 if is_64bit else 32,
            "endianness": "Little-Endian" if ei_data == 1 else "Big-Endian",
            "file_type": e_type_map.get(e_type_val, f"Unknown (0x{e_type_val:x})"),
            "machine": e_machine_map.get(e_machine_val, f"Unknown (0x{e_machine_val:x})"),
            "entry_point": hex(e_entry),
        }

    def inspect_pe(self) -> Dict[str, Any]:
        """Parse PE headers using pefile or native struct parsing."""
        hdr = self._raw_header
        if len(hdr) < 64 or hdr[:2] != b"MZ":
            return {}

        e_lfanew = struct.unpack("<I", hdr[60:64])[0]
        if self.size < e_lfanew + 24:
            return {"format": "PE", "error": "Corrupted PE header (truncated)"}

        with open(self.path, "rb") as f:
            f.seek(e_lfanew)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                return {"format": "PE", "error": "Invalid PE signature"}
            coff_hdr = f.read(20)

        machine, num_sections, time_date, _, _, opt_hdr_size, characteristics = struct.unpack(
            "<HHIIIHH", coff_hdr
        )

        pe_machine_map = {
            0x014C: "x86 (32-bit)",
            0x8664: "x86_64 (AMD64)",
            0x01C0: "ARM",
            0xAA64: "ARM64",
        }

        return {
            "format": "PE",
            "machine": pe_machine_map.get(machine, f"Unknown (0x{machine:x})"),
            "sections_count": num_sections,
            "timestamp": time_date,
            "characteristics": hex(characteristics),
        }

    def get_symbols_summary(self) -> Dict[str, Any]:
        """Extract imported/exported symbols using nm / objdump if available."""
        result: Dict[str, Any] = {"imports": [], "exports": [], "total_symbols": 0}
        try:
            p = subprocess.run(
                ["nm", "-D", "--demangle", str(self.path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if p.returncode == 0:
                for line in p.stdout.splitlines()[:200]:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        sym_type = parts[-2]
                        sym_name = parts[-1]
                        if sym_type in ("U", "w"):
                            result["imports"].append(sym_name)
                        elif sym_type in ("T", "W", "D", "B"):
                            result["exports"].append(sym_name)
                result["total_symbols"] = len(result["imports"]) + len(result["exports"])
        except Exception:
            pass
        return result

    def full_triage(self) -> Dict[str, Any]:
        """Perform full fast triage of the target binary."""
        fmt = self.detect_format()
        triage_data: Dict[str, Any] = {
            "filepath": str(self.path),
            "filename": self.path.name,
            "size_bytes": self.size,
            "size_human": f"{self.size / (1024 * 1024):.2f} MB" if self.size > 1024*1024 else f"{self.size / 1024:.2f} KB",
            "format": fmt,
        }

        if fmt == "ELF":
            triage_data.update(self.inspect_elf())
            triage_data["symbols"] = self.get_symbols_summary()
        elif fmt == "PE":
            triage_data.update(self.inspect_pe())
        else:
            from rea_titan.core.firmware import FirmwareUnpacker
            fw = FirmwareUnpacker(self.path).detect_and_unpack()
            triage_data["firmware_analysis"] = fw
            if fw.get("unpacked"):
                triage_data["format"] = fw.get("format", "Hardware/Firmware Config")
            triage_data["notes"] = fw.get("notes", "Raw binary or unpacked image. Detailed entropy and strings scan recommended.")

        return triage_data
