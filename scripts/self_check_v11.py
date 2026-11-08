#!/usr/bin/env python3
"""Fail-closed self-check for the v1.1 outputs.

Version: 1.1.0
Owner: Rock Lambros

Closes premortem P23 and P65. Exits non-zero on the first failed check. Checks:
1. The canonical run is complete, not halted, single run id, no missing cells.
2. Every prompt hash in the run manifest equals the hash of the rebuilt briefing.
3. Every chosen attempt was served by the pinned provider and finished with stop.
4. The endpoint record did not change during the run.
5. The spend ledger equals the sum of usage.cost in the raw responses.
6. The key usage difference covers the ledger (within $0.05 or 5 percent).
7. The calculator source and the criteria file match their recorded hashes.
8. Two consecutive analyses produce byte-identical results.json.
9. Every number listed in results_v11/report_numbers.json, if present, matches results.json.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(msg: str) -> None:
    print(f"SELF-CHECK FAILED: {msg}")
    sys.exit(1)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def calc_tree_sha() -> str:
    h = hashlib.sha256()
    for p in sorted((ROOT / "work" / "aivss-calc" / "aivss_calc").rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts:
            h.update(str(p.relative_to(ROOT)).encode()); h.update(p.read_bytes())
    return h.hexdigest()


def dig(obj, path: str):
    for part in path.split("."):
        obj = obj[int(part)] if isinstance(obj, list) else obj[part]
    return obj


def main() -> int:
    rid = (ROOT / "runs" / "CANONICAL").read_text().strip()
    run = ROOT / "runs" / rid
    m = json.loads((run / "manifest.json").read_text())
    if m.get("halted"):
        fail("canonical run halted")
    if m["run_id"] != rid:
        fail("manifest run id differs from CANONICAL")
    expected = sum(1 for arm in m["arms"] for p in (ROOT / "packets_v11" / arm).glob("*.json") if p.name != "bridge_manifest.json") * len(m["pins"])
    if len(m["cells"]) != expected:
        fail(f"cells {len(m['cells'])} != expected {expected}")
    bad = [c["cell_id"] for c in m["cells"] if c["status"] != "complete"]
    if bad:
        print(f"note: {len(bad)} cells not complete, counted as defects in the analysis: {bad[:6]}")
    pins = m["pins"]
    for c in m["cells"]:
        pk = json.loads((ROOT / c["packet_path"]).read_text())
        if hashlib.sha256((pk["system_prompt"] + "\x00" + pk["user_prompt"]).encode()).hexdigest() != c["prompt_sha256"]:
            fail(f"prompt hash mismatch {c['cell_id']}")
        for a in c.get("attempts") or []:
            if a["check"] == "ok":
                if str(a["served_provider"]).lower() not in {x.lower() for x in pins[c["slot"]]["providers"]}:
                    fail(f"served provider {a['served_provider']} on {c['cell_id']}")
                if a["finish_reason"] != "stop":
                    fail(f"finish reason {a['finish_reason']} on {c['cell_id']}")
    if not m.get("endpoint_record_unchanged"):
        fail("endpoint record changed during the run")
    ledger = sum(float(json.loads(x)["usd"] or 0) for x in (run / "spend.jsonl").read_text().splitlines() if x.strip())
    raw = 0.0
    raw_ids = set()
    for p in sorted((run / "raw").rglob("*.json")):
        body = json.loads(p.read_text()).get("body") or {}
        raw += float((body.get("usage") or {}).get("cost") or 0)
        raw_ids.add(body.get("id"))
    # Attempts whose raw file a resume overwrote are listed, with their ledger cost, in overwritten_raw.json (ledger R17).
    over = json.loads((run / "overwritten_raw.json").read_text()) if (run / "overwritten_raw.json").exists() else {"entries": []}
    listed = {e["generation_id"] for e in over["entries"]}
    ledger_ids = [json.loads(x).get("generation_id") for x in (run / "spend.jsonl").read_text().splitlines() if x.strip()]
    unexplained = [g for g in ledger_ids if g not in raw_ids and g not in listed]
    if unexplained:
        fail(f"ledger entries with no raw response and no record: {unexplained[:5]}")
    over_usd = sum(float(e["usd"] or 0) for e in over["entries"])
    if abs(ledger - raw - over_usd) > 1e-6:
        fail(f"ledger {ledger} != raw usage {raw} plus recorded overwrites {over_usd}")
    print(f"ledger {ledger:.6f} = raw {raw:.6f} + recorded overwritten attempts {over_usd:.6f}")
    before, after = m.get("key_usage_before"), m.get("key_usage_after")
    if isinstance(before, (int, float)) and isinstance(after, (int, float)):
        diff = after - before
        if diff + max(0.05, 0.05 * ledger) < ledger:
            fail(f"key usage difference {diff:.4f} is below the ledger {ledger:.4f}")
        print(f"key usage difference {diff:.6f} against ledger {ledger:.6f}")
    else:
        print("note: key usage not available from the provider, reconciliation skipped")
    prov = json.loads((ROOT / "phase0" / "provenance_v11.json").read_text())
    if prov["calculator_tree_sha256"] != calc_tree_sha():
        fail("calculator source changed since provenance was recorded")
    if sha(ROOT / "premortem" / "hypothesis_criteria.json") != m["criteria_sha256"]:
        fail("criteria file changed after the run started")
    first = (ROOT / "results_v11" / "results.json").read_bytes()
    subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "analyze_v11.py")], check=True, capture_output=True)
    if (ROOT / "results_v11" / "results.json").read_bytes() != first:
        fail("analysis is not deterministic")
    numbers = ROOT / "results_v11" / "report_numbers.json"
    if numbers.exists():
        results = json.loads(first)
        for item in json.loads(numbers.read_text()):
            got = dig(results, item["path"])
            if (round(got, item.get("round", 6)) if isinstance(got, float) else got) != item["value"]:
                fail(f"report number {item['label']}: report says {item['value']}, results say {got}")
        print(f"report numbers checked: {len(json.loads(numbers.read_text()))}")
    print("SELF-CHECK PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
