"""Ghidra headless automation and execution wrapper."""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from rea_titan.config import ANALYZE_HEADLESS, PROJECTS_DIR, SCRIPTS_DIR


class GhidraHeadlessEngine:
    """Automates Ghidra analyzeHeadless for headless decompilation."""

    def __init__(self, headless_path: Optional[Path] = None):
        self.headless = headless_path or ANALYZE_HEADLESS
        if not self.headless or not Path(self.headless).is_file():
            raise RuntimeError(
                "Ghidra analyzeHeadless not found. Ensure Ghidra is installed or set GHIDRA_HOME."
            )
        self.scripts_dir = SCRIPTS_DIR

    def decompile_binary(
        self,
        binary_path: str | Path,
        output_json: Optional[str | Path] = None,
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        """Run analyzeHeadless with TitanExportJson.java and parse JSON results."""
        target = Path(binary_path).resolve()
        if not target.is_file():
            raise FileNotFoundError(f"Binary not found: {target}")

        if not output_json:
            temp_json = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            output_json_path = Path(temp_json.name)
            temp_json.close()
        else:
            output_json_path = Path(output_json).resolve()

        project_dir = PROJECTS_DIR / f"proj_{target.stem}"
        project_dir.mkdir(parents=True, exist_ok=True)
        project_name = f"titan_{target.stem}"

        cmd = [
            str(self.headless),
            str(project_dir),
            project_name,
            "-import",
            str(target),
            "-overwrite",
            "-scriptPath",
            str(self.scripts_dir),
            "-postScript",
            "TitanExportJson.java",
            str(output_json_path),
        ]

        custom_env = os.environ.copy()
        custom_env["JAVA_HOME"] = os.environ.get("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-amd64")
        custom_env["PATH"] = f"{custom_env['JAVA_HOME']}/bin:{custom_env.get('PATH', '')}"

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                env=custom_env,
            )

            if output_json_path.is_file() and output_json_path.stat().st_size > 0:
                with open(output_json_path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                return {
                    "status": "success",
                    "data": data,
                    "stdout_sample": process.stdout[-500:] if process.stdout else "",
                }
            else:
                return {
                    "status": "error",
                    "message": "Ghidra completed but did not produce JSON output.",
                    "stderr": process.stderr,
                    "stdout": process.stdout[-1000:],
                }

        except subprocess.TimeoutExpired:
            return {"status": "error", "message": f"Ghidra timed out after {timeout_seconds} seconds."}
        except Exception as e:
            return {"status": "error", "message": str(e)}
        finally:
            if not output_json and output_json_path.is_file():
                try:
                    os.unlink(output_json_path)
                except OSError:
                    pass
