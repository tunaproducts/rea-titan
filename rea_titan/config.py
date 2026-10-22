"""REA-TITAN Configuration and Environment Detector."""

import os
import shutil
from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKSPACE = Path.home() / "rea_titan_workspace"
PROJECTS_DIR = DEFAULT_WORKSPACE / "projects"
OUTPUT_DIR = DEFAULT_WORKSPACE / "output"

DEFAULT_WORKSPACE.mkdir(parents=True, exist_ok=True)
PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Common Ghidra installation candidates
GHIDRA_CANDIDATE_PATHS = [
    Path("/home/murat/ghidra_12.1.4_PUBLIC"),
    Path.home() / "ghidra_12.1.4_PUBLIC",
    Path("/opt/ghidra"),
    Path("/usr/share/ghidra"),
]


def find_ghidra_home() -> Path | None:
    """Find the Ghidra installation directory."""
    env_ghidra = os.environ.get("GHIDRA_HOME")
    if env_ghidra and Path(env_ghidra).is_dir():
        return Path(env_ghidra)

    for candidate in GHIDRA_CANDIDATE_PATHS:
        if candidate.is_dir() and (candidate / "support" / "analyzeHeadless").is_file():
            return candidate

    # Search in home directory
    for match in Path.home().glob("ghidra*"):
        if match.is_dir() and (match / "support" / "analyzeHeadless").is_file():
            return match

    return None


def get_headless_analyzer() -> Path | None:
    """Get the path to analyzeHeadless executable."""
    ghidra_home = find_ghidra_home()
    if ghidra_home:
        headless = ghidra_home / "support" / "analyzeHeadless"
        if headless.is_file():
            return headless
    which_headless = shutil.which("analyzeHeadless")
    return Path(which_headless) if which_headless else None


GHIDRA_HOME = find_ghidra_home()
ANALYZE_HEADLESS = get_headless_analyzer()
SCRIPTS_DIR = Path(__file__).resolve().parent / "ghidra" / "scripts"
