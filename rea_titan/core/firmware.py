"""Firmware, config unpacker, and specialized hardware triage plugin."""

import base64
import os
import zlib
from pathlib import Path
from typing import Any, Dict, Optional


class FirmwareUnpacker:
    """Specialized engine for decoding and unpacking hardware configs and firmware blobs."""

    def __init__(self, filepath: str | Path):
        self.path = Path(filepath).resolve()
        with open(self.path, "rb") as f:
            self.raw_data = f.read()

    def detect_and_unpack(self) -> Dict[str, Any]:
        """Detect special signatures like ZTE / Huawei router configs and compressed payloads."""
        results: Dict[str, Any] = {"format": "Generic Binary", "unpacked": False}

        # Check if the entire file is Base64 encoded (e.g., ZTE H3600P / H298A config.bin)
        try:
            trimmed = self.raw_data.strip()
            if len(trimmed) % 4 == 0 and all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n" for c in trimmed[:1024]):
                decoded = base64.b64decode(trimmed)
                if len(decoded) > 16:
                    # Check ZTE Magic: \x04\x03\x02\x01
                    if decoded[:4] == b"\x04\x03\x02\x01":
                        header_str = decoded[12:32].decode("latin-1", errors="ignore").strip("\x00")
                        results["format"] = f"ZTE Router Config Binary ({header_str})"
                        results["unpacked"] = True
                        results["decoded_size"] = len(decoded)
                        results["notes"] = "ZTE config header detected. Contains encrypted/compressed XML settings payload."
                        
                        # Save unpacked binary
                        unpacked_path = self.path.with_suffix(".decoded.bin")
                        with open(unpacked_path, "wb") as out:
                            out.write(decoded)
                        results["unpacked_file"] = str(unpacked_path)
                        return results
        except Exception:
            pass

        # Check for embedded zlib / gzip streams
        zlib_offsets = []
        for i in range(len(self.raw_data) - 4):
            if self.raw_data[i:i+2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
                try:
                    decompressor = zlib.decompressobj()
                    decomp = decompressor.decompress(self.raw_data[i:i+65536])
                    if len(decomp) > 64:
                        zlib_offsets.append(hex(i))
                        if len(zlib_offsets) >= 5:
                            break
                except Exception:
                    continue

        if zlib_offsets:
            results["embedded_zlib_streams"] = zlib_offsets
            results["notes"] = f"Detected {len(zlib_offsets)} valid zlib streams."

        return results
