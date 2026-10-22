"""Advanced License Verification, Anti-Tamper & Anti-Debugging Engine.

Specialized in discovering validation bottlenecks, timing-leak compares, and anti-analysis traps.
"""

from pathlib import Path
from typing import Any, Dict, List
import re
import subprocess

# Known Anti-Debugging & Environment Integrity APIs
ANTI_DEBUG_APIS = {
    # Linux Tricks
    "ptrace": {
        "platform": "Linux",
        "technique": "Process Trace Detection (PTRACE_TRACEME)",
        "bypass": "LD_PRELOAD fake ptrace or NOP call.",
    },
    "prctl": {
        "platform": "Linux",
        "technique": "Dumpable flag restrictions (PR_SET_DUMPABLE)",
        "bypass": "Interception via Frida or LD_PRELOAD.",
    },
    # Windows Tricks
    "IsDebuggerPresent": {
        "platform": "Windows",
        "technique": "PEB BeingDebugged flag check",
        "bypass": "Set PEB.BeingDebugged = 0 or ScyllaHide.",
    },
    "CheckRemoteDebuggerPresent": {
        "platform": "Windows",
        "technique": "ProcessDebugPort query via kernel",
        "bypass": "Hook API or kernel driver emulation.",
    },
    "NtQueryInformationProcess": {
        "platform": "Windows",
        "technique": "Native API ProcessDebugPort (0x7) / DebugFlags (0x1f)",
        "bypass": "Return status STATUS_SUCCESS with DebugPort=0.",
    },
    "OutputDebugStringA": {
        "platform": "Windows",
        "technique": "LastError manipulation to detect debugger listener",
        "bypass": "SetLastError hooking.",
    },
    "FindWindow": {
        "platform": "Windows",
        "technique": "Searching for debugger window titles (x64dbg, IDA Pro, Cheat Engine)",
        "bypass": "Rename debugger titles or hook FindWindowA/W.",
    },
}

# License / Key Checking Patterns
KEY_CHECK_STRINGS = [
    "license", "serial", "activation", "regkey", "product_key",
    "invalid key", "access denied", "access granted", "unregistered",
    "trial expired", "hwid", "hardware_id", "machine_guid"
]

COMPARE_APIS = ["strcmp", "strncmp", "memcmp", "wcscmp", "lstrcmp", "StrCmpIA"]


class LicenseAndAntiTamperAuditor:
    """Specialized analyzer for key-validation systems and anti-debugging mechanisms."""

    def __init__(self, filepath: str | Path):
        self.path = Path(filepath).resolve()
        with open(self.path, "rb") as f:
            self.data = f.read()

    def audit_anti_debugging(self) -> Dict[str, Any]:
        """Detect anti-debugging and anti-analysis mechanisms."""
        detected = []

        # Check API imports and binary string references
        for api, meta in ANTI_DEBUG_APIS.items():
            if api.encode("ascii") in self.data:
                detected.append({
                    "api": api,
                    "platform": meta["platform"],
                    "technique": meta["technique"],
                    "bypass_strategy": meta["bypass"],
                })

        # Check for /proc/self/status or TracerPid detection on Linux
        has_proc_status = b"/proc/self/status" in self.data or b"TracerPid" in self.data
        if has_proc_status:
            detected.append({
                "api": "/proc/self/status",
                "platform": "Linux",
                "technique": "TracerPid inspection to detect active debugger process",
                "bypass_strategy": "Hook fopen/read for /proc/self/status to return TracerPid: 0.",
            })

        # Check for RDTSC timing checks
        has_rdtsc = b"\x0f\x31" in self.data
        if has_rdtsc:
            detected.append({
                "api": "RDTSC",
                "platform": "x86/x64",
                "technique": "CPU cycle counter check to detect single-stepping in debugger",
                "bypass_strategy": "Use hypervisor RDTSC interceptor or patch timing delta jump.",
            })

        return {
            "anti_debug_mechanisms_count": len(detected),
            "mechanisms": detected,
            "has_protection": len(detected) > 0,
        }

    def audit_key_validation_flow(self) -> Dict[str, Any]:
        """Discover key verification logic, hardcoded tokens, and timing-attack comparison bugs."""
        found_key_strings = []
        lower_data = self.data.lower()

        for term in KEY_CHECK_STRINGS:
            term_b = term.encode("ascii")
            if term_b in lower_data:
                found_key_strings.append(term)

        # Detect comparison functions
        used_compare_apis = [api for api in COMPARE_APIS if api.encode("ascii") in self.data]

        # Timing attack vulnerability: standard strcmp/memcmp instead of constant time
        has_timing_leak_risk = len(used_compare_apis) > 0

        return {
            "validation_indicators": found_key_strings,
            "comparison_apis_used": used_compare_apis,
            "timing_attack_vulnerability": {
                "vulnerable": has_timing_leak_risk,
                "reason": (
                    "Application uses standard non-constant-time comparisons (e.g. strcmp/memcmp). "
                    "Byte-by-byte early return enables side-channel timing analysis."
                    if has_timing_leak_risk
                    else "No standard non-constant comparison APIs identified."
                ),
                "remediation": "Replace strcmp/memcmp with constant-time equality check (e.g., CRYPTO_memcmp)."
            },
            "validation_architecture": (
                "High Probability of Client-Side Key Checking"
                if (found_key_strings and used_compare_apis)
                else "Server-Side or Heavily Obfuscated Validation"
            ),
        }

    def full_audit(self) -> Dict[str, Any]:
        return {
            "anti_debugging": self.audit_anti_debugging(),
            "key_verification": self.audit_key_validation_flow(),
        }
