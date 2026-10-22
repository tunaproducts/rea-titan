"""Deep string extraction, secret mining, and regex-based entity categorizer."""

import re
from pathlib import Path
from typing import Any, Dict, List


URL_REGEX = re.compile(r"https?://[a-zA-Z0-9_\-\./~%#?&=:+]+")
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
FILEPATH_REGEX = re.compile(r"(?:/[a-zA-Z0-9_.\-]+){2,}|(?:[a-zA-Z]:\\[a-zA-Z0-9_.\-\\]+)")
KEY_PATTERN = re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")
TOKEN_REGEX = re.compile(r"\b(?:Bearer\s+[a-zA-Z0-9_\-\.]+|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})\b")


class StringMiner:
    """Extracts strings and filters secrets/endpoints from binary files."""

    def __init__(self, filepath: str | Path, min_length: int = 5):
        self.path = Path(filepath).resolve()
        self.min_length = min_length
        with open(self.path, "rb") as f:
            self.data = f.read()

    def extract_raw_strings(self) -> List[str]:
        """Extract ASCII and simple Unicode strings."""
        ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(self.min_length).encode() + rb",}")
        ascii_strings = [m.group(0).decode("latin-1", errors="ignore") for m in ascii_pattern.finditer(self.data)]
        return ascii_strings

    def mine_secrets_and_endpoints(self) -> Dict[str, Any]:
        """Scan extracted strings for interesting reverse-engineering targets."""
        all_strings = self.extract_raw_strings()
        full_text = "\n".join(all_strings)

        urls = list(set(URL_REGEX.findall(full_text)))
        ips = list(set(IPV4_REGEX.findall(full_text)))
        paths = list(set(FILEPATH_REGEX.findall(full_text)))
        tokens = list(set(TOKEN_REGEX.findall(full_text)))
        has_private_key = bool(KEY_PATTERN.search(full_text))

        interesting_commands = [
            s for s in all_strings
            if any(cmd in s.lower() for cmd in ["system(", "popen", "/bin/sh", "/bin/bash", "cmd.exe", "powershell", "sudo ", "curl "])
        ]

        return {
            "total_strings_count": len(all_strings),
            "urls": urls[:30],
            "ips": ips[:30],
            "file_paths": paths[:30],
            "tokens": tokens,
            "has_private_key": has_private_key,
            "shell_commands_and_exec": interesting_commands[:20],
            "sample_strings": all_strings[:50],
        }
