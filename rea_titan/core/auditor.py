"""Automated Vulnerability & Dangerous API Security Auditor for Binaries."""

from pathlib import Path
from typing import Any, Dict, List
import subprocess


UNSAFE_FUNCTIONS = {
    # High/Critical Risk Functions
    "gets": {
        "severity": "CRITICAL",
        "description": "Never use gets(). Lacks bounds checking and causes trivial buffer overflows.",
        "remediation": "Replace with fgets(buf, sizeof(buf), stdin)."
    },
    "strcpy": {
        "severity": "HIGH",
        "description": "Unbounded string copy. Vulnerable to stack/heap buffer overflow.",
        "remediation": "Use strncpy, strlcpy, or snprintf."
    },
    "strcat": {
        "severity": "HIGH",
        "description": "Unbounded string concatenation. Can easily overflow destination buffer.",
        "remediation": "Use strncat or strlcat."
    },
    "sprintf": {
        "severity": "HIGH",
        "description": "Unbounded formatted output. Vulnerable to buffer overflow.",
        "remediation": "Use snprintf with explicit destination size."
    },
    "vsprintf": {
        "severity": "HIGH",
        "description": "Unbounded variable formatted output.",
        "remediation": "Use vsnprintf."
    },
    "system": {
        "severity": "HIGH",
        "description": "Executes shell command. Vulnerable to command injection if input is untrusted.",
        "remediation": "Use execve / posix_spawn with hardcoded argument arrays."
    },
    "popen": {
        "severity": "MEDIUM",
        "description": "Spawns process with shell pipe. Vulnerable to command injection.",
        "remediation": "Use pipe() and fork/exec with sanitized input."
    },
    "scanf": {
        "severity": "MEDIUM",
        "description": "%s specifier without field width causes buffer overflow.",
        "remediation": "Specify maximum field width (e.g., %255s) or use fgets."
    },
    "rand": {
        "severity": "LOW",
        "description": "Linear congruential PRNG is cryptographically predictable.",
        "remediation": "Use /dev/urandom, getrandom(), or OpenSSL RAND_bytes()."
    },
}


class SecurityAuditor:
    """Audits binary for security vulnerabilities, unsafe APIs, and architectural weaknesses."""

    def __init__(self, filepath: str | Path):
        self.path = Path(filepath).resolve()

    def audit_apis(self) -> Dict[str, Any]:
        """Scan imported and exported symbols for known hazardous C APIs."""
        findings: List[Dict[str, Any]] = []

        # Read symbols using nm / strings
        symbols_found = set()
        try:
            p = subprocess.run(
                ["nm", "-D", str(self.path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if p.returncode == 0:
                for line in p.stdout.splitlines():
                    parts = line.strip().split()
                    if parts:
                        symbols_found.add(parts[-1])
        except Exception:
            pass

        # Fallback to binary byte scanning for static binaries
        with open(self.path, "rb") as f:
            data = f.read()

        for func, meta in UNSAFE_FUNCTIONS.items():
            func_bytes = func.encode("ascii")
            if func in symbols_found or (b"\x00" + func_bytes + b"\x00" in data):
                findings.append({
                    "function": func,
                    "severity": meta["severity"],
                    "description": meta["description"],
                    "remediation": meta["remediation"],
                })

        # Calculate security posture score (100 is best)
        penalty = sum(30 if f["severity"] == "CRITICAL" else 15 if f["severity"] == "HIGH" else 5 for f in findings)
        score = max(0, 100 - penalty)

        return {
            "vulnerability_score": f"{score}/100",
            "findings_count": len(findings),
            "findings": findings,
            "summary": (
                "Binary uses secure APIs." if not findings
                else f"Identified {len(findings)} potentially hazardous standard library calls."
            ),
        }
