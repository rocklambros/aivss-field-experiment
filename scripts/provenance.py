#!/usr/bin/env python3
"""Record repo, OS, interpreter, and package provenance for the experiment.

Version: 1.0.0
Owner: Rock Lambros
Purpose: Write phase0/provenance.json from read-only git queries and the
    installed package metadata of the experiment venv.

Only read-only git subcommands run here (rev-parse, log, remote get-url).
The four repos are read-only inputs to the experiment.
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
from importlib import metadata
from pathlib import Path

REPOS = (
    "damn-vulnerable-ai-agent",
    "agent-sec-lab",
    "finbot-ctf-demo",
    "owasp-aivss",
)
PACKAGES = ("aivss-calc", "cvss", "jsonschema", "pytest")


def _run(args: list[str]) -> str:
    """Run a command and return stripped stdout, or an error marker."""
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable: {exc.__class__.__name__}"
    if done.returncode != 0:
        return f"unavailable: exit {done.returncode}"
    return done.stdout.strip()


def _version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "not installed"


def _pytest_summary(log: Path) -> dict[str, object]:
    """Parse the final pytest summary line from the saved Phase 0 log."""
    if not log.exists():
        return {"summary_line": None, "passed": None, "skipped": None, "failed": None}
    lines = [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    last = lines[-1] if lines else ""
    counts = {
        key: int(m.group(1)) if (m := re.search(rf"(\d+) {key}", last)) else 0
        for key in ("passed", "skipped", "failed")
    }
    return {"summary_line": last, **counts}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: provenance.py <root_dir> <experiment_dir>", file=sys.stderr)
        return 2
    root, exp = Path(argv[1]), Path(argv[2])
    repos = {}
    for name in REPOS:
        path = str(root / name)
        repos[name] = {
            "commit": _run(["git", "-C", path, "rev-parse", "HEAD"]),
            "commit_date": _run(["git", "-C", path, "log", "-1", "--format=%cd", "--date=iso"]),
            "remote": _run(["git", "-C", path, "remote", "get-url", "origin"]),
        }
    verify_log = exp / "phase0" / "verify.log"
    try:
        verify = json.loads(verify_log.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        verify = None
    out = {
        "repos": repos,
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "macos_version": platform.mac_ver()[0] or None,
        },
        "python": platform.python_version(),
        "docker": _run(["docker", "--version"]),
        "packages": {name: _version(name) for name in PACKAGES},
        "calculator_tests": _pytest_summary(exp / "phase0" / "pytest.log"),
        "calculator_verify": verify,
        "prior_analysis_expectation": {"passed": 223, "skipped": 4, "verify_passed": True},
    }
    target = exp / "phase0" / "provenance.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
