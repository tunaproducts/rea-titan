"""High-speed sliding window Shannon entropy scanner and packing detector."""

import math
from pathlib import Path
from typing import Any, Dict, List, Tuple


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte array (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1

    entropy = 0.0
    for count in frequencies:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy


class EntropyScanner:
    """Sliding-window entropy analyzer for binaries and firmware."""

    def __init__(self, filepath: str | Path, block_size: int = 4096, step: int = 4096):
        self.path = Path(filepath).resolve()
        self.block_size = block_size
        self.step = step
        self.file_size = self.path.stat().st_size

    def scan(self) -> Dict[str, Any]:
        """Perform sliding window entropy scan and classify regions."""
        blocks: List[Dict[str, Any]] = []
        high_entropy_regions: List[Dict[str, Any]] = []
        low_entropy_regions: List[Dict[str, Any]] = []

        total_bytes = 0
        overall_freq = [0] * 256

        with open(self.path, "rb") as f:
            offset = 0
            while True:
                data = f.read(self.block_size)
                if not data:
                    break

                for b in data:
                    overall_freq[b] += 1
                total_bytes += len(data)

                ent = calculate_entropy(data)
                classification = "Plain/Code"
                if ent >= 7.2:
                    classification = "Encrypted / Packed (High)"
                    high_entropy_regions.append({"offset": hex(offset), "entropy": round(ent, 3)})
                elif ent <= 2.0:
                    classification = "Padded / Sparse (Low)"
                    low_entropy_regions.append({"offset": hex(offset), "entropy": round(ent, 3)})

                blocks.append({
                    "offset": hex(offset),
                    "size": len(data),
                    "entropy": round(ent, 3),
                    "type": classification,
                })

                offset += len(data)

        # Overall file entropy
        overall_entropy = 0.0
        if total_bytes > 0:
            for count in overall_freq:
                if count > 0:
                    p = count / total_bytes
                    overall_entropy -= p * math.log2(p)

        is_packed = overall_entropy >= 7.0 or len(high_entropy_regions) > (len(blocks) * 0.4)

        return {
            "overall_entropy": round(overall_entropy, 3),
            "is_packed_or_encrypted": is_packed,
            "total_blocks": len(blocks),
            "high_entropy_count": len(high_entropy_regions),
            "high_entropy_regions": high_entropy_regions[:10],
            "sample_blocks": blocks[:15],
            "recommendation": (
                "Binary appears packed/encrypted. Consider unpacker/cryptographic key extraction."
                if is_packed
                else "Binary entropy is standard. Ready for immediate decompilation."
            ),
        }
