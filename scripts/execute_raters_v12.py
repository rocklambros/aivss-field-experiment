#!/usr/bin/env python3
"""v1.1 rerun: send pre-rendered briefings to the three pinned assessors.

Version: 1.3.0
Owner: Rock Lambros

Closes premortem P11 to P13, P60 to P65 (fix_plan.md sections D and R2.1 to R2.4).

- Routing is frozen to the v1.0 pins. The full endpoint record is locked before
  the run and diffed after it. Any change halts. No substitution.
- Prompts come pre-rendered and hashed from packets_v11/. The runner sends them
  unchanged and does not parse or repair output.
- Every attempt's full HTTP body goes to runs/<run_id>/raw/. A spend line is
  written as soon as the response arrives, before any check.
- One identical retry per cell when the content is not a JSON object or
  finish_reason is not stop. Both attempts are kept and billed.
- Per-run cap, per-call halt, and the $500 total cap across every ledger.
- The OpenRouter key comes from `pass` and lives only in process memory.

Usage: execute_raters_v12.py --run-id v11-YYYYMMDDTHHMMSSZ [--arms base,retest,...] [--resume]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
PACKETS = ROOT / "packets_v11"
RUNS = ROOT / "runs"
CHAT_URL = "https://openrouter.ai/api/v1/chat/completions"
KEY_URL = "https://openrouter.ai/api/v1/key"
# Seven reasoning assessors, owner decision 2026-11-07 (ledger R14). Every assessor reasons at the
# same effort setting so agreement is not confounded by reasoning setup.
# Endpoint policy, owner ruling R15 (2026-11-07): the Chinese-origin assessors (D, E, G) use US
# endpoints only. The others list a US endpoint first and may fall back to a listed non-US endpoint of
# the same model. Fallback is still restricted to the listed tags (allow_fallbacks stays off).
PINS = {
    "A": {"model": "openai/gpt-6.1-sol", "tags": ["azure/us", "openai"], "providers": ["Azure", "OpenAI"], "us_only": False},
    "B": {"model": "google/gemini-4-argon", "tags": ["google-vertex/us", "google-vertex/global"], "providers": ["Google"], "us_only": False},
    "C": {"model": "x-ai/grok-4.7", "tags": ["xai/zdr/us", "amazon-bedrock/global"], "providers": ["xAI", "Amazon Bedrock"], "us_only": False},
    "D": {"model": "qwen/qwen3.8-max-0902", "tags": ["alibaba/us-east-1"], "providers": ["Alibaba"], "us_only": True},
    "E": {"model": "z-ai/glm-5.3", "tags": ["wafer/us"], "providers": ["Wafer"], "us_only": True},
    "F": {"model": "anthropic/claude-sonnet-5.5", "tags": ["amazon-bedrock/us-east-1", "anthropic"], "providers": ["Amazon Bedrock", "Anthropic"], "us_only": False},
    "G": {"model": "deepseek/deepseek-v4-pro", "tags": ["azure/us"], "providers": ["Azure"], "us_only": True},
}
REASONING = {"effort": "high"}
ENDPOINT_FIELDS = ("tag", "provider_name", "status", "quantization", "context_length", "max_completion_tokens",
                   "max_prompt_tokens", "supported_parameters", "pricing")
TOTAL_CAP_USD = 500.0
RUN_CAP_USD = 200.0
CALL_HALT_USD = 1.00  # 64000 tokens at the highest listed price is about $0.70
V10_SPEND_USD = 5.466454  # sum of usage.cost in the 144 v1.0 result files (premortem P11)
MAX_TOKENS = {"default": 64000}  # reasoning tokens count toward this; 32000 truncated 8 calls (ledger R16)
WORKERS_PER_SLOT = 8
TIMEOUT = httpx.Timeout(connect=30.0, read=1500.0, write=60.0, pool=60.0)
DEFECT_STOP_RATE = 0.15
ARMS = ("base", "retest", "ablation", "fixed")

_lock = threading.Lock()
_halt = threading.Event()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def get_key() -> str:
    key = subprocess.run(["pass", "show", "openrouter/api-key"], capture_output=True, text=True, check=True).stdout.strip()
    if not key:
        raise SystemExit("pass returned an empty key")
    return key


def headers(key: str) -> dict:
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json",
            "HTTP-Referer": "https://localhost/aivss-experiment", "X-Title": "AIVSS field experiment v1.1"}


def endpoint_record(key: str, model: str, tags: list[str]) -> dict:
    url = f"https://openrouter.ai/api/v1/models/{model}/endpoints"
    with httpx.Client(timeout=60) as client:
        resp = client.get(url, headers=headers(key))
    resp.raise_for_status()
    found = {ep.get("tag"): {f: ep.get(f) for f in ENDPOINT_FIELDS} for ep in resp.json()["data"]["endpoints"] if ep.get("tag") in tags}
    missing = [t_ for t_ in tags if t_ not in found]
    if missing:
        raise SystemExit(f"pinned endpoints {model} {missing} not listed")
    return found


def stable_part(lock: dict) -> dict:
    """The endpoint record minus availability, which legitimately changes during a run."""
    return {s: {tag: {k: v for k, v in rec.items() if k != "status"} for tag, rec in tags.items()} for s, tags in lock.items()}


def key_usage(key: str) -> float | None:
    with httpx.Client(timeout=60) as client:
        resp = client.get(KEY_URL, headers=headers(key))
    if resp.status_code >= 400:
        return None
    data = resp.json().get("data") or {}
    return data.get("usage")


def spent_all(run_dir: Path) -> float:
    total = V10_SPEND_USD
    for ledger in RUNS.glob("v11-*/spend.jsonl"):
        for line in ledger.read_text().splitlines():
            try:
                total += float(json.loads(line).get("usd") or 0)
            except (ValueError, json.JSONDecodeError):
                continue
    return total


def spent_run(run_dir: Path) -> float:
    ledger = run_dir / "spend.jsonl"
    if not ledger.exists():
        return 0.0
    return sum(float(json.loads(x).get("usd") or 0) for x in ledger.read_text().splitlines() if x.strip())


def load_cells(arms: list[str]) -> list[dict]:
    cells = []
    for arm in arms:
        for path in sorted((PACKETS / arm).glob("*.json")):
            if path.name == "bridge_manifest.json":
                continue
            pk = json.loads(path.read_text())
            for slot in PINS:
                cells.append({"cell_id": f"{arm}/{slot}/{pk['finding_id']}", "arm": arm, "slot": slot,
                              "finding_id": pk["finding_id"], "packet_path": str(path.relative_to(ROOT)),
                              "prompt_sha256": pk["prompt_sha256"]})
    return cells


def call_once(key: str, slot: str, arm: str, system: str, user: str) -> tuple[dict | None, dict]:
    pin = PINS[slot]
    payload = {
        "model": pin["model"],
        "temperature": 0,
        "max_tokens": MAX_TOKENS.get(arm, MAX_TOKENS["default"]),
        "provider": {"order": list(pin["tags"]), "allow_fallbacks": False},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    payload["reasoning"] = dict(REASONING)
    started = time.time()
    meta = {"request": {k: v for k, v in payload.items() if k != "messages"}, "started": now()}
    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            resp = client.post(CHAT_URL, headers=headers(key), json=payload)
        meta["http_status"] = resp.status_code
        body = resp.json() if resp.content else {}
    except (httpx.HTTPError, ValueError) as exc:
        meta["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
        body = None
    meta["elapsed_s"] = round(time.time() - started, 2)
    return body, meta


def run_cell(key: str, cell: dict, run_dir: Path) -> dict:
    pk = json.loads((ROOT / cell["packet_path"]).read_text())
    system, user = pk["system_prompt"], pk["user_prompt"]
    if hashlib.sha256((system + "\x00" + user).encode()).hexdigest() != cell["prompt_sha256"]:
        raise SystemExit(f"{cell['cell_id']}: prompt hash mismatch")
    attempts = []
    for attempt in (1, 2):
        if _halt.is_set():
            return {**cell, "status": "halted", "attempts": attempts}
        body, meta = call_once(key, cell["slot"], cell["arm"], system, user)
        raw_path = run_dir / "raw" / cell["arm"] / cell["slot"] / f"{cell['finding_id']}.attempt{attempt}.json"
        resume_n = 0
        while raw_path.exists():
            # Never overwrite a saved response (ledger R17): a resumed cell gets a new file name.
            resume_n += 1
            raw_path = raw_path.with_name(f"{cell['finding_id']}.r{resume_n}.attempt{attempt}.json")
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(json.dumps({"cell": cell, "meta": meta, "body": body}, indent=2))
        usage = (body or {}).get("usage") or {}
        cost = float(usage.get("cost") or 0)
        with _lock:
            with (run_dir / "spend.jsonl").open("a") as fh:
                fh.write(json.dumps({"ts": now(), "cell": cell["cell_id"], "attempt": attempt, "usd": cost,
                                     "generation_id": (body or {}).get("id"), "http_status": meta.get("http_status")}) + "\n")
            if cost > CALL_HALT_USD or spent_run(run_dir) > RUN_CAP_USD or spent_all(run_dir) > TOTAL_CAP_USD:
                _halt.set()
        served = (body or {}).get("provider")
        served = served.get("name") if isinstance(served, dict) else served
        choice = ((body or {}).get("choices") or [{}])[0]
        content = (choice.get("message") or {}).get("content") or ""
        finish = choice.get("finish_reason")
        check = "ok"
        if not body or meta.get("http_status", 0) >= 400:
            check = "http_error"
        elif body.get("error"):
            # A provider-side refusal such as a safety block. Data, not a routing failure (protocol: log refusals).
            err = body["error"]
            check = "refused_by_provider" if "SAFETY" in str(err).upper() or "content_policy" in str(err).lower() else "provider_error"
        elif str(served).lower() not in {p_.lower() for p_ in PINS[cell["slot"]]["providers"]}:
            check = "wrong_provider"
            _halt.set()
        elif finish != "stop":
            check = f"finish_{finish}"
        else:
            try:
                if not isinstance(json.loads(content), dict):
                    check = "not_object"
            except json.JSONDecodeError:
                check = "not_json"
        attempts.append({"attempt": attempt, "raw": str(raw_path.relative_to(ROOT)), "check": check,
                         "served_provider": served, "finish_reason": finish, "cost": cost,
                         "reasoning_tokens": ((usage.get("completion_tokens_details") or {}).get("reasoning_tokens")),
                         "completion_tokens": usage.get("completion_tokens"), "elapsed_s": meta["elapsed_s"]})
        if check == "ok":
            return {**cell, "status": "complete", "attempts": attempts}
        if check == "wrong_provider":
            break
    return {**cell, "status": "error", "attempts": attempts}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--arms", default=",".join(ARMS))
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--only", default="", help="comma-separated finding ids (dry run)")
    args = ap.parse_args()
    arms = [a for a in args.arms.split(",") if a]
    run_dir = RUNS / args.run_id
    manifest_path = run_dir / "manifest.json"
    if run_dir.exists() and not args.resume:
        raise SystemExit(f"{run_dir} exists. Use --resume to continue the same run.")
    run_dir.mkdir(parents=True, exist_ok=True)
    key = get_key()

    lock = {slot: endpoint_record(key, p["model"], p["tags"]) for slot, p in PINS.items()}
    for slot, rec in lock.items():
        if not any(r["status"] == 0 for r in rec.values()):
            raise SystemExit(f"no listed endpoint for {slot} is up: {rec}")
    lock_path = run_dir / "routing.lock.json"
    if lock_path.exists() and stable_part(json.loads(lock_path.read_text())["endpoints"]) != stable_part(lock):
        raise SystemExit("endpoint record changed since this run started. Halting.")

    cells = load_cells(arms)
    if args.only:
        keep = set(args.only.split(","))
        cells = [c for c in cells if c["finding_id"] in keep]
    if args.resume and manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        manifest.setdefault("resumes", []).append({"at": now(), "script_sha256": sha_file(Path(__file__)), "max_tokens": MAX_TOKENS})
        done = {c["cell_id"]: c for c in manifest["cells"] if c["status"] == "complete"}
        old_sha = {c["cell_id"]: c["prompt_sha256"] for c in manifest["cells"]}
        for c in cells:
            if c["cell_id"] in old_sha and old_sha[c["cell_id"]] != c["prompt_sha256"]:
                raise SystemExit(f"{c['cell_id']}: prompt changed since the run started. Halting.")
    else:
        manifest = {"run_id": args.run_id, "version": "1.3.0", "started": now(), "arms": arms,
                    "script_sha256": sha_file(Path(__file__)),
                    "packet_manifest_sha256": sha_file(PACKETS / "manifest.json"),
                    "criteria_sha256": sha_file(ROOT / "premortem" / "hypothesis_criteria.json"),
                    "pins": PINS, "max_tokens": MAX_TOKENS, "reasoning": REASONING, "key_usage_before": key_usage(key), "cells": []}
        lock_path.write_text(json.dumps({"locked_at": now(), "endpoints": lock}, indent=2))
        done = {}
    todo = [c for c in cells if c["cell_id"] not in done]
    print(f"{now()} run {args.run_id}: {len(cells)} cells, {len(done)} already complete, {len(todo)} to send", flush=True)

    results = dict(done)
    pools = {slot: ThreadPoolExecutor(max_workers=WORKERS_PER_SLOT) for slot in PINS}
    futures = {pools[c["slot"]].submit(run_cell, key, c, run_dir): c for c in todo}
    finished = 0
    for fut in as_completed(futures):
        res = fut.result()
        results[res["cell_id"]] = res
        finished += 1
        if finished % 10 == 0 or res["status"] != "complete":
            print(f"{now()} {finished}/{len(todo)} {res['cell_id']} {res['status']} run ${spent_run(run_dir):.4f}", flush=True)
        with _lock:
            manifest["cells"] = sorted(results.values(), key=lambda c: c["cell_id"])
            manifest_path.write_text(json.dumps(manifest, indent=2))
        base = [r for r in results.values() if r["arm"] == "base"]
        for slot in PINS:
            mine = [r for r in base if r["slot"] == slot]
            if len(mine) >= 10 and sum(r["status"] == "error" for r in mine) / len(mine) > DEFECT_STOP_RATE:
                print(f"{now()} defect stop rule: assessor {slot} base error rate above {DEFECT_STOP_RATE}", flush=True)
                _halt.set()
    for pool in pools.values():
        pool.shutdown(wait=True)

    after = {slot: endpoint_record(key, p["model"], p["tags"]) for slot, p in PINS.items()}
    manifest["endpoint_record_unchanged"] = stable_part(after) == stable_part(lock)
    manifest["endpoint_status_at_end"] = {s: {t_: r["status"] for t_, r in v.items()} for s, v in after.items()}
    manifest["key_usage_after"] = key_usage(key)
    manifest["finished"] = now()
    manifest["halted"] = _halt.is_set()
    manifest["spend_run_usd"] = round(spent_run(run_dir), 6)
    status = {}
    for c in manifest["cells"]:
        status[c["status"]] = status.get(c["status"], 0) + 1
    manifest["status_counts"] = status
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"{now()} done {status} spend ${manifest['spend_run_usd']} endpoints unchanged {manifest['endpoint_record_unchanged']} halted {manifest['halted']}", flush=True)
    return 0 if not manifest["halted"] and status.get("error", 0) == 0 else 3


if __name__ == "__main__":
    sys.exit(main())
