"""Local demo server for OWASP ASI Top 10 AIVSS dashboard."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import __version__
from .assessment import assess, assessment_from_payload
from .scenarios import SCENARIOS, scenario_payload
from .web_bundle import BUNDLE_NAME, manifest, package_zip

REPO_ROOT = Path(__file__).resolve().parent.parent
WEB_ROOT = REPO_ROOT / "web"
EXAMPLES = REPO_ROOT / "examples"


def _top10_payload() -> list[dict]:
    rows = []
    for scenario in SCENARIOS:
        payload = scenario_payload(scenario["risk_category"], tool_version=__version__)
        report = assess(assessment_from_payload(payload))
        decision = report.get("decision", {})
        scores = report["scores"]
        rows.append(
            {
                "asi": scenario["risk_category"],
                "name": report["risk_category"]["name"],
                "title": scenario["title"],
                "cvss_vector": report["cvss"]["vector"],
                "aivss_vector": report["agentic_ai_profile"]["vector"],
                "cvss_bte": scores["cvss_bte"],
                "cvss_nomenclature": scores["cvss_nomenclature"],
                "aivss": scores["aivss"],
                "aivss_band": scores["aivss_band"],
                "agentic_uplift_u": scores["agentic_uplift_u"],
                "status": scores["status"],
                "agentic_effect_class": report["agentic_ai_profile"]["agentic_effect_class"],
                "decision_basis": decision.get("decision_basis"),
                "ssvc": decision.get("ssvc"),
                "bod_timeline": (
                    decision.get("bod_2604_timeline")
                    or decision.get("bod_2604_analogy_timeline")
                    or decision.get("bod_2604_guidance_timeline")
                ),
                "bod_timeline_label": (
                    decision.get("bod_2604_label")
                    or decision.get("bod_2604_analogy_label")
                    or decision.get("bod_2604_guidance_label")
                ),
                "aivss_recommended_timeline": decision.get("aivss_recommended_timeline"),
                "aivss_recommended_label": decision.get("aivss_recommended_label"),
                "overlay_triggered": decision.get("overlay_triggered"),
                "escalated": decision.get("escalated"),
            }
        )
    return rows


class DemoHandler(BaseHTTPRequestHandler):
    server_version = f"AIVSS-Demo/{__version__}"

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _send_json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, data: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, path: Path, content_type: str) -> None:
        if not path.is_file():
            self.send_error(404)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        route = unquote(parsed.path)

        if route == "/api/top10":
            self._send_json(_top10_payload())
            return

        if route.startswith("/api/scenario/"):
            asi = route.split("/")[-1].upper()
            try:
                payload = scenario_payload(asi, tool_version=__version__)
            except KeyError:
                self.send_error(404)
                return
            report = assess(assessment_from_payload(payload))
            self._send_json({"input": payload, "report": report})
            return

        if route == "/py/manifest.json":
            self._send_json(manifest())
            return

        if route == f"/py/{BUNDLE_NAME}":
            self._send_bytes(package_zip(), "application/zip")
            return

        if route in ("/", "/index.html"):
            self._send_file(WEB_ROOT / "index.html", "text/html; charset=utf-8")
            return

        if route == "/favicon.ico":
            self._send_file(WEB_ROOT / "favicon.ico", "image/x-icon")
            return

        if route.startswith("/web/"):
            rel = route.removeprefix("/web/")
            target = (WEB_ROOT / rel).resolve()
            if not str(target).startswith(str(WEB_ROOT.resolve())):
                self.send_error(403)
                return
            suffix = target.suffix.lower()
            ctype = {
                ".css": "text/css; charset=utf-8",
                ".js": "application/javascript; charset=utf-8",
                ".json": "application/json; charset=utf-8",
                ".svg": "image/svg+xml",
                ".ico": "image/x-icon",
                ".png": "image/png",
            }.get(suffix, "application/octet-stream")
            self._send_file(target, ctype)
            return

        self.send_error(404)


def run_demo(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = ThreadingHTTPServer((host, port), DemoHandler)
    url = f"http://{host}:{port}/"
    print(f"AIVSS OWASP ASI Top 10 demo: {url}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
