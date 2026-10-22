"""Signature and constant scanner for cryptographic algorithms, compilers, and packers."""

import re
from pathlib import Path
from typing import Any, Dict, List


CRYPTO_SIGNATURES = {
    "AES S-Box": bytes([
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    ]),
    "AES Inverse S-Box": bytes([
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
        0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    ]),
    "ChaCha20 / Salsa20 Constant": b"expand 32-byte k",
    "SHA-256 Initial Constants": bytes([
        0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85,
        0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A,
    ]),
    "MD5 Round Constants": bytes([
        0xD7, 0x6A, 0xA4, 0x78, 0xE8, 0xC7, 0xB7, 0x56,
        0x24, 0x20, 0x70, 0xDB, 0xC1, 0xBD, 0xCE, 0xEE,
    ]),
}

PACKER_COMPILER_PATTERNS = {
    "UPX Packed": [b"UPX0", b"UPX1", b"UPX!"],
    "Golang Runtime": [b"runtime.main", b"Go buildinf:", b"go.buildid"],
    "Rust Binary": [b"rust_panic", b"library/core/src/panicking"],
    "PyInstaller Executable": [b"pyi-windows-sleep", b"MEI\x0c\x0b\x0a\x0b", b"pydata"],
    ".NET / Mono Assembly": [b"mscoree.dll", b"_CorExeMain", b"BSJB"],
}


class SignatureDetector:
    """Scans raw binaries for cryptographic tables, compiler fingerprints, and packers."""

    def __init__(self, filepath: str | Path):
        self.path = Path(filepath).resolve()
        with open(self.path, "rb") as f:
            self.data = f.read()

    def scan(self) -> Dict[str, Any]:
        detected_crypto: List[Dict[str, str]] = []
        detected_compilers: List[str] = []

        # Check crypto
        for name, pattern in CRYPTO_SIGNATURES.items():
            pos = self.data.find(pattern)
            if pos != -1:
                detected_crypto.append({"algorithm": name, "offset": hex(pos)})

        # Check compiler / packer
        for tag, patterns in PACKER_COMPILER_PATTERNS.items():
            for pat in patterns:
                if pat in self.data:
                    if tag not in detected_compilers:
                        detected_compilers.append(tag)
                    break

        return {
            "crypto_algorithms": detected_crypto,
            "packers_and_compilers": detected_compilers,
            "has_crypto": len(detected_crypto) > 0,
            "has_known_packer": any("Packed" in c for c in detected_compilers),
        }
