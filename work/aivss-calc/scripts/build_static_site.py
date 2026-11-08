"""Build static site artifact for GitHub Pages."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WEB_ROOT = REPO_ROOT / "web"
DEFAULT_OUT = REPO_ROOT / "_site"
DEFAULT_BASE = "/aivss-v1-candidate/"


def build(out_dir: Path, base_href: str = DEFAULT_BASE) -> None:
    from aivss_calc import __version__
    from aivss_calc.assessment import assess, assessment_from_payload
    from aivss_calc.demo_server import _top10_payload
    from aivss_calc.scenarios import SCENARIOS, scenario_payload
    from aivss_calc.web_bundle import BUNDLE_NAME, manifest, package_zip

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    web_out = out_dir / "web"
    web_out.mkdir()

    for path in WEB_ROOT.iterdir():
        if path.is_dir():
            if path.name == "assets":
                shutil.copytree(path, out_dir / "assets", dirs_exist_ok=True)
            continue
        if path.suffix in {".css", ".js"}:
            shutil.copy2(path, web_out / path.name)
        else:
            shutil.copy2(path, out_dir / path.name)

    data_dir = out_dir / "data"
    data_dir.mkdir()
    data_dir.joinpath("top10.json").write_text(
        json.dumps(_top10_payload(), indent=2) + "\n",
        encoding="utf-8",
    )
    for scenario in SCENARIOS:
        asi = scenario["risk_category"]
        payload = scenario_payload(asi, tool_version=__version__)
        report = assess(assessment_from_payload(payload))
        detail = {"input": payload, "report": report}
        data_dir.joinpath(f"{asi.lower()}.json").write_text(
            json.dumps(detail, indent=2) + "\n",
            encoding="utf-8",
        )

    py_dir = out_dir / "py"
    py_dir.mkdir()
    py_dir.joinpath(BUNDLE_NAME).write_bytes(package_zip())
    py_dir.joinpath("manifest.json").write_text(
        json.dumps(manifest(), indent=2) + "\n",
        encoding="utf-8",
    )

    index_path = out_dir / "index.html"
    html = index_path.read_text(encoding="utf-8")
    base_tag = f'  <base href="{base_href}" />\n'
    if "<base " not in html:
        html = html.replace("<head>", f"<head>\n{base_tag}", 1)
    index_path.write_text(html, encoding="utf-8")


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    base = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_BASE
    build(out, base)
