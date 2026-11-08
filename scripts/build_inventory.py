#!/usr/bin/env python3
"""Validate and render the Phase 1 inventory.

Version: 1.0.0
Owner: Rock Lambros
Purpose: Check every file-and-line citation in the lab profiles and findings
    against the repos, merge the per-lab findings into findings.json, and
    render profile.md and findings.md.

The per-lab JSON files under labs/<lab>/ are the source of truth. This script
only reads the four repos. It never writes outside the experiment folder.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

LABS = ("finbot-ctf-demo", "agent-sec-lab", "damn-vulnerable-ai-agent")

# JSON keys whose string values are file-and-line citations.
CITATION_LIST_KEYS = frozenset({"citations", "source_citations", "code_citations", "paths"})
CITATION_SCALAR_KEYS = frozenset({"citation"})

CITATION_RE = re.compile(r"^(?P<path>[^:]+?)(?::(?P<start>\d+)(?:-(?P<end>\d+))?)?$")


def iter_citations(node: Any, trail: str = "") -> Iterator[tuple[str, str]]:
    """Yield (json_trail, citation) for every citation string in a document."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{trail}.{key}" if trail else key
            if key in CITATION_LIST_KEYS and isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        yield here, item
            elif key in CITATION_SCALAR_KEYS and isinstance(value, str):
                yield here, value
            else:
                yield from iter_citations(value, here)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from iter_citations(item, f"{trail}[{index}]")


class LineCounter:
    """Cache file line counts so each cited file is read once."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._counts: dict[Path, int | None] = {}

    def count(self, rel: str) -> int | None:
        path = self.root / rel
        if path not in self._counts:
            try:
                with path.open("rb") as handle:
                    self._counts[path] = sum(1 for _ in handle)
            except OSError:
                self._counts[path] = None
        return self._counts[path]


def check_citation(citation: str, counter: LineCounter) -> str | None:
    """Return an error message for a bad citation, or None when it resolves."""
    match = CITATION_RE.match(citation)
    if not match:
        return "not in path:line or path:start-end form"
    total = counter.count(match["path"])
    if total is None:
        return "file not found"
    if match["start"] is None:
        return None
    start = int(match["start"])
    end = int(match["end"]) if match["end"] else start
    if start < 1 or end < start:
        return "line range is not ordered"
    if end > total:
        return f"line {end} is past the end of the file ({total} lines)"
    return None


def load(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"build_inventory: cannot load {path}: {exc}") from exc


def cell(text: Any) -> str:
    """Escape a value for a Markdown table cell."""
    return str(text if text is not None else "none").replace("|", "\\|").replace("\n", " ")


def cites(items: list[str]) -> str:
    return ", ".join(f"`{item}`" for item in items)


def render_profile(profile: dict[str, Any]) -> str:
    out = [f"# Lab profile: {profile['lab']}", "", f"Repo: {profile['repo']}", "", profile["summary"], ""]

    default = profile["default_configuration"]
    out += ["## Default configuration", "", default["description"], "", f"Evidence: {cites(default['citations'])}", ""]
    if "llm_mode" in profile:
        llm = profile["llm_mode"]
        out += ["## Optional LLM mode", "", llm["description"], "", f"Evidence: {cites(llm['citations'])}", ""]

    out += ["## Agents", ""]
    for agent in profile["agents"]:
        if "ids" in agent:
            name = ", ".join(agent["ids"])
            out += [f"- **{name}** (port {agent['port']}, {agent['protocol']}, label {agent['security_label']}). "
                    f"{agent['role']} Evidence: {cites(agent['citations'])}"]
        else:
            out += [
                f"### {agent['name']} (`{agent['id']}`)", "",
                f"- Role: {agent['role']}",
                f"- Framework: {agent['framework']}",
                f"- Model provider: {agent['model_provider']}",
                f"- Loop: {agent['loop']}",
            ]
            if "fallback_mode" in agent:
                out += [f"- Fallback: {agent['fallback_mode']}"]
            out += [
                f"- System prompt: {agent['system_prompt']['description']} "
                f"Evidence: {cites(agent['system_prompt']['citations'])}",
                f"- Evidence: {cites(agent['citations'])}", "",
            ]
    out += [""]

    out += ["## Applicability questions", ""]
    if "applicability" in profile:
        out += ["| Agents | Reading | Model-directed goal pursuit | Selects or sequences actions | Confidence | Rationale |",
                "|---|---|---|---|---|---|"]
        for group in profile["applicability"]:
            names = ", ".join(group["agents"])
            for label, key in (("As implemented (default)", "as_implemented_default"), ("As modeled (persona)", "as_modeled_persona")):
                reading = group[key]
                out += [f"| {cell(names)} | {label} | {cell(reading['model_directed_goal_pursuit'])} | "
                        f"{cell(reading['action_selection_or_sequencing'])} | {reading['confidence']} | {cell(reading['rationale'])} |"]
            if "llm_mode_note" in group:
                out += [f"| {cell(names)} | LLM mode note | | | | {cell(group['llm_mode_note'])} |"]
        out += ["", "Evidence: " + cites(sorted({c for g in profile["applicability"] for c in g["citations"]})), ""]
    else:
        out += ["| Agent | Model-directed goal pursuit | Selects or sequences actions | Confidence | Rationale |", "|---|---|---|---|---|"]
        for agent in profile["agents"]:
            app = agent["applicability"]
            out += [f"| {agent['id']} | {cell(app['model_directed_goal_pursuit'])} | {cell(app['action_selection_or_sequencing'])} | "
                    f"{app['confidence']} | {cell(app['rationale'])} Evidence: {cites(app['citations'])} |"]
        out += [""]

    out += ["## Tools", "", "| Tool | Capability | What it does | Evidence |", "|---|---|---|---|"]
    for tool in profile["tools"]:
        out += [f"| {cell(tool['name'])} | {cell(tool['capability'])} | {cell(tool['description'])} | {cites(tool['citations'])} |"]
    binding = profile["tool_binding"]
    out += ["", f"Tool binding: {binding['description']} Evidence: {cites(binding['citations'])}", ""]

    out += ["## Data sources and grounding", "", "| Source | Trust | Description | Evidence |", "|---|---|---|---|"]
    for source in profile["data_sources"]:
        out += [f"| {cell(source['name'])} | {cell(source['trust'])} | {cell(source['description'])} | {cites(source['citations'])} |"]
    out += [""]

    for title, key, lead_key in (
        ("Memory persistence", "memory", "persistence"),
        ("Multi-agent handoffs", "multi_agent", "handoffs"),
        ("Human approval", "human_approval", None),
        ("Deployment", "deployment", None),
        ("Fixed configuration documented by the lab", "fixed_configuration", None),
        ("Lab severity labels", "lab_severity_labels", None),
        ("Exploit artifacts in the repo", "exploit_artifacts", None),
    ):
        if key not in profile:
            continue
        section = profile[key]
        out += [f"## {title}", ""]
        if lead_key:
            out += [f"Value: {section[lead_key]}.", ""]
        out += [section["description"], "", f"Evidence: {cites(section['citations'])}", ""]

    out += ["## Identities and credentials", ""]
    for item in profile["identities_and_credentials"]:
        out += [f"- {item['item']}. Evidence: {cites(item['citations'])}"]
    exposure = profile["exposure"]
    out += ["", "## Exposure", "", f"- Public endpoint: {exposure['public_endpoint']}", f"- Authentication: {exposure['auth']}",
            f"- Evidence: {cites(exposure['citations'])}", ""]

    out += ["## Text addressed to an AI assistant (observed, not followed)", ""]
    if profile.get("injection_text_observed"):
        for item in profile["injection_text_observed"]:
            out += [f"- `{item['citation']}`: \"{item['quote']}\" {item['handling']}"]
    else:
        out += ["None found."]
    if profile.get("notes"):
        out += ["", "## Notes", ""] + [f"- {note}" for note in profile["notes"]]
    return "\n".join(out) + "\n"


def render_findings(merged: dict[str, Any]) -> str:
    counts = merged["counts"]
    out = [
        "# Findings inventory (Phase 1)", "",
        "One finding per vulnerability, challenge, or attack that a lab documents. Each finding is one exploit path.",
        "Nothing here is scored yet. Static-check labels are inferred from reading code, not from running it.", "",
        "## Counts", "", "| Lab | Scored findings | Documented, not scored | Suspected, not scored |", "|---|---|---|---|",
    ]
    for lab in LABS:
        c = counts[lab]
        out += [f"| {lab} | {c['findings']} | {c['documented_not_scored']} | {c['suspected_not_scored']} |"]
    out += [f"| **Total** | **{counts['total_findings']}** | | |", ""]

    for lab in LABS:
        block = merged["labs"][lab]
        out += [f"## {lab}", "", f"Source: {block['source_document']}", ""]
        if block.get("implementation_note"):
            out += [block["implementation_note"], ""]
        out += ["| ID | Title | Agent | ASI | Entry point | Sink | Exploit in repo | Lab severity | Path group |", "|---|---|---|---|---|---|---|---|---|"]
        for f in block["findings"]:
            poc = f["poc"]
            poc_text = f"yes ({poc['kind']})" if poc["in_repo"] else "no"
            out += [f"| {f['id']} | {cell(f['title'])} | {f['agent']} | {f['asi_category']} | {cell(f['entry_point'])} | "
                    f"{cell(f['sink'])} | {cell(poc_text)} | {cell(f['lab_severity'])} | {cell(f['path_group'])} |"]
        out += [""]

        for f in block["findings"]:
            out += [f"### {f['id']}: {f['title']}", "", f"- Path id: `{f['path_id']}`", f"- Lab label: {f['lab_label']}",
                    f"- Entry point: {f['entry_point']}", "- Steps:"]
            out += [f"  {n}. {step}" for n, step in enumerate(f["steps"], start=1)]
            out += [f"- Sink: {f['sink']}", f"- Impact: {f['impact']}", "- Preconditions: " + " ".join(f["preconditions"])]
            if f.get("variants"):
                out += ["- Variants: " + ", ".join(v.rstrip(".") for v in f["variants"]) + "."]
            if f.get("default_mode_static_check"):
                out += [f"- Default-mode static check (inferred): {f['default_mode_static_check']}"]
            poc = f["poc"]
            out += [f"- Exploit or proof of concept in repo: {'yes' if poc['in_repo'] else 'no'} ({poc['kind']}). {poc['note']}"
                    + (f" Files: {cites(poc['paths'])}" if poc["paths"] else "")]
            if f.get("fixed_config"):
                fx = f["fixed_config"]
                out += [f"- Fixed configuration: {fx['name']}. {fx['summary']} Evidence: {cites(fx['citations'])}"]
            out += [f"- Source: {cites(f['source_citations'])}", f"- Code: {cites(f['code_citations'])}"]
            for note in f.get("notes", []):
                out += [f"- Note: {note}"]
            out += [""]

        out += [f"### {lab}: documented, not scored", ""]
        if block["documented_not_scored"]:
            out += [f"- **{d['label']}.** {d['reason']} Evidence: {cites(d['citations'])}" for d in block["documented_not_scored"]]
        else:
            out += ["None."]
        out += ["", f"### {lab}: suspected, not scored", ""]
        if block["suspected_not_scored"]:
            out += [f"- {s['issue']} Status: {s['status']}. Evidence: {cites(s['citations'])}" for s in block["suspected_not_scored"]]
        else:
            out += ["None."]
        out += [""]
    return "\n".join(out) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: build_inventory.py <root_dir> <experiment_dir>", file=sys.stderr)
        return 2
    root, exp = Path(argv[1]), Path(argv[2])
    counter = LineCounter(root)

    errors: list[str] = []
    checked = 0
    merged: dict[str, Any] = {"labs": {}, "counts": {}, "findings": []}
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()

    for lab in LABS:
        profile = load(exp / "labs" / lab / "profile.json")
        findings = load(exp / "labs" / lab / "findings.json")
        for name, doc in (("profile.json", profile), ("findings.json", findings)):
            for trail, citation in iter_citations(doc):
                checked += 1
                problem = check_citation(citation, counter)
                if problem:
                    errors.append(f"{lab}/{name} {trail}: {citation}: {problem}")
        for finding in findings["findings"]:
            if finding["id"] in seen_ids:
                errors.append(f"{lab}: duplicate finding id {finding['id']}")
            if finding["path_id"] in seen_paths:
                errors.append(f"{lab}: duplicate path_id {finding['path_id']}")
            seen_ids.add(finding["id"])
            seen_paths.add(finding["path_id"])
            merged["findings"].append({"lab": lab, **finding})
        merged["labs"][lab] = findings
        merged["counts"][lab] = {
            "findings": len(findings["findings"]),
            "documented_not_scored": len(findings["documented_not_scored"]),
            "suspected_not_scored": len(findings["suspected_not_scored"]),
        }
        (exp / "labs" / lab / "profile.md").write_text(render_profile(profile), encoding="utf-8")

    if errors:
        # Fail closed. A citation that does not resolve breaks the evidence rule.
        print(f"build_inventory: {len(errors)} citation or id errors out of {checked} citations", file=sys.stderr)
        for line in errors:
            print(f"  {line}", file=sys.stderr)
        return 1

    merged["counts"]["total_findings"] = len(merged["findings"])
    merged["citations_checked"] = checked
    (exp / "findings.json").write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    (exp / "findings.md").write_text(render_findings(merged), encoding="utf-8")
    print(f"citations checked: {checked}, errors: 0")
    for lab in LABS:
        print(f"{lab}: {merged['counts'][lab]}")
    print(f"total findings: {merged['counts']['total_findings']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
