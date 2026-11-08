#!/usr/bin/env python3
"""Rebuild the v1.0 assessor prompts for the bridge arm.

Version: 1.1.0
Owner: Rock Lambros

Writes the v1.0 runner as committed in 68c86f3 to packets_v11/bridge/ as an
audit snapshot, imports SYSTEM_PROMPT, USER_TEMPLATE, and packet_for_rater
from it, and applies them, with the v1.0 rubric and the v1.0 truncation
(rubric 12,000 characters, packet JSON 24,000 characters), to the v1.0
packets in runs/v1.0/packets. v1.0 stored no prompt or prompt hash, and the
runner was first committed after the v1.0 run, so byte identity with what
v1.0 sent cannot be proven. The bridge arm separates model drift and runner
change from packet change under that stated limit (premortem P60).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V10_COMMIT = "68c86f3"
OUT = ROOT / "packets_v11" / "bridge"
SNAPSHOT = OUT / "v10_runner_snapshot.py"


def load_v10_runner():
    src = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{V10_COMMIT}:scripts/execute_raters_secure.py"],
        capture_output=True, text=True, check=True,
    ).stdout
    SNAPSHOT.write_text(src, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("v10_runner_snapshot", SNAPSHOT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # top level only defines constants and functions; main() is not called
    return module, hashlib.sha256(src.encode()).hexdigest()


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    v10, runner_sha = load_v10_runner()
    rows = []
    for path in sorted((ROOT / "runs" / "v1.0" / "packets").glob("*.json")):
        packet = json.loads(path.read_text())
        rubric = packet.get("rubric_text") or ""
        if len(rubric) > 12000:
            rubric = rubric[:12000]
        user = v10.USER_TEMPLATE.format(rubric=rubric, packet=json.dumps(v10.packet_for_rater(packet), indent=2)[:24000])
        system = v10.SYSTEM_PROMPT
        sha = hashlib.sha256((system + "\x00" + user).encode()).hexdigest()
        record = {"packet_id": packet["finding_id"] + "~bridge", "finding_id": packet["finding_id"], "arm": "bridge",
                  "system_prompt": system, "user_prompt": user, "prompt_sha256": sha}
        (OUT / f"{packet['finding_id']}.json").write_text(json.dumps(record, indent=2))
        rows.append({"packet_id": record["packet_id"], "prompt_sha256": sha, "prompt_chars": len(system) + len(user)})
    (OUT / "bridge_manifest.json").write_text(json.dumps({
        "v10_runner_commit": V10_COMMIT, "v10_runner_sha256": runner_sha,
        "byte_identity_with_v10": "unverifiable, v1.0 stored no prompts", "packets": rows}, indent=2))
    print(f"bridge prompts {len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
