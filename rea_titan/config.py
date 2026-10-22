"""REA-TITAN Configuration and Cross-Platform Environment Detector (Windows 10/11 & Linux/Kali)."""

import os
import platform
import shutil
import sys
from pathlib import Path

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKSPACE = Path.home() / "rea_titan_workspace"
PROJECTS_DIR = DEFAULT_WORKSPACE / "projects"
OUTPUT_DIR = DEFAULT_WORKSPACE / "output"

DEFAULT_WORKSPACE.mkdir(parents=True, exist_ok=True)
PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def get_candidate_ghidra_paths():
    """Return candidates for Ghidra installations across Windows and Linux."""
    candidates = []
    if IS_WINDOWS:
        system_drive = os.environ.get("SystemDrive", "C:")
        candidates.extend([
            Path(f"{system_drive}\\ghidra"),
            Path(f"{system_drive}\\tools\\ghidra"),
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "ghidra",
            Path.home() / "ghidra",
        ])
        for p in Path(f"{system_drive}\\").glob("ghidra*"):
            candidates.append(p)
    else:
        candidates.extend([
            Path("/home/murat/ghidra_12.1.4_PUBLIC"),
            Path.home() / "ghidra_12.1.4_PUBLIC",
            Path("/opt/ghidra"),
            Path("/usr/share/ghidra"),
        ])
        for match in Path.home().glob("ghidra*"):
            candidates.append(match)

    return candidates


def find_ghidra_home() -> Path | None:
    """Find the Ghidra installation directory."""
    env_ghidra = os.environ.get("GHIDRA_HOME")
    if env_ghidra and Path(env_ghidra).is_dir():
        return Path(env_ghidra)

    headless_bin = "analyzeHeadless.bat" if IS_WINDOWS else "analyzeHeadless"

    for candidate in get_candidate_ghidra_paths():
        if candidate.is_dir() and (candidate / "support" / headless_bin).is_file():
            return candidate

    return None


def get_headless_analyzer() -> Path | None:
    """Get the path to analyzeHeadless executable."""
    headless_bin = "analyzeHeadless.bat" if IS_WINDOWS else "analyzeHeadless"
    ghidra_home = find_ghidra_home()
    if ghidra_home:
        headless = ghidra_home / "support" / headless_bin
        if headless.is_file():
            return headless

    which_headless = shutil.which(headless_bin)
    return Path(which_headless) if which_headless else None


GHIDRA_HOME = find_ghidra_home()
ANALYZE_HEADLESS = get_headless_analyzer()
SCRIPTS_DIR = Path(__file__).resolve().parent / "ghidra" / "scripts"
