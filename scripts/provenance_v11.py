#!/usr/bin/env python3
"""Record v1.1 provenance: repo commits, packages, calculator source hash, test results.

Version: 1.1.0
Owner: Rock Lambros

Writes phase0/provenance_v11.json. Read-only git queries only.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from self_check_v11 import calc_tree_sha  # noqa: E402


def run(args: list[str]) -> str:
    done = subprocess.run(args, capture_output=True, text=True)
    return done.stdout.strip() if done.returncode == 0 else f"unavailable: exit {done.returncode}"


def main() -> int:
    repos = {}
    for name in ("damn-vulnerable-ai-agent", "agent-sec-lab", "finbot-ctf-demo", "owasp-aivss"):
        path = str(ROOT.parent / name)
        repos[name] = {"commit": run(["git", "-C", path, "rev-parse", "HEAD"]), "remote": run(["git", "-C", path, "remote", "get-url", "origin"])}
    pytest_out = run([sys.executable, "-m", "pytest", "-q", str(ROOT / "work" / "aivss-calc" / "tests"), "-p", "no:cacheprovider"])
    verify = run([str(Path(sys.executable).parent / "aivss-calc"), "verify"])
    out = {
        "repos": repos, "python": platform.python_version(), "os": f"{platform.system()} {platform.release()} {platform.machine()}",
        "packages": {p: metadata.version(p) for p in ("aivss-calc", "cvss", "jsonschema", "httpx", "matplotlib", "python-docx", "nbformat", "nbconvert")},
        "calculator_tree_sha256": calc_tree_sha(),
        "requirements_lock_sha256": hashlib.sha256((ROOT / "requirements.lock").read_bytes()).hexdigest(),
        "pytest_summary": pytest_out.splitlines()[-1] if pytest_out else None,
        "verify_passed": '"passed": true' in verify,
    }
    (ROOT / "phase0" / "provenance_v11.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps({k: out[k] for k in ("pytest_summary", "verify_passed", "calculator_tree_sha256")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
