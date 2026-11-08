"""HTTP smoke tests for the demo dashboard."""

from __future__ import annotations

import json
import shutil
import threading
from http.client import HTTPConnection
from pathlib import Path

from aivss_calc.demo_server import DemoHandler
from http.server import ThreadingHTTPServer

REPO_ROOT = Path(__file__).resolve().parent.parent


def _with_server(test_fn):
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        test_fn(host, port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get(host: str, port: int, path: str) -> tuple[int, bytes]:
    conn = HTTPConnection(host, port, timeout=30)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body


def test_demo_index_and_assets():
    def run(host, port):
        for path in (
            "/",
            "/favicon.ico",
            "/web/style.css",
            "/web/app.js",
            "/web/engine.js",
            "/web/hints.js",
            "/web/calculator.js",
            "/py/aivss_calc.zip",
        ):
            status, body = _get(host, port, path)
            assert status == 200, path
            assert body, path

    _with_server(run)


def test_demo_top10_api():
    def run(host, port):
        status, body = _get(host, port, "/api/top10")
        assert status == 200
        rows = json.loads(body)
        assert len(rows) == 10
        assert rows[0]["asi"] == "ASI01"
        assert rows[0]["aivss"] == 9.7
        assert rows[0]["cvss_bte"] == 9.2
        assert "escalated" in rows[0]
        # ASI01 is A1 here, so the A2-only overlay does not trigger.
        assert rows[0]["overlay_triggered"] is False
        # A2 at 3D ceiling: overlay_triggered but not escalated
        asi10 = next(r for r in rows if r["asi"] == "ASI10")
        assert asi10["overlay_triggered"] is True
        assert asi10["escalated"] is False

    _with_server(run)


def test_demo_python_bundle_manifest():
    def run(host, port):
        status, body = _get(host, port, "/py/manifest.json")
        assert status == 200
        manifest = json.loads(body)
        assert manifest["bundle"] == "py/aivss_calc.zip"
        assert manifest["pyodide_index_url"].startswith("https://cdn.jsdelivr.net/pyodide/")
        assert manifest["packages"] and manifest["packages"][0].startswith("cvss==")

    _with_server(run)


def test_static_build_includes_web_assets():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "build_static_site",
        REPO_ROOT / "scripts" / "build_static_site.py",
    )
    build_mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(build_mod)

    out = REPO_ROOT / "_site_test"
    build_mod.build(out)
    try:
        for path in (
            out / "index.html",
            out / "favicon.ico",
            out / "web" / "style.css",
            out / "web" / "app.js",
            out / "web" / "engine.js",
            out / "web" / "hints.js",
            out / "web" / "calculator.js",
            out / "data" / "top10.json",
            out / "py" / "aivss_calc.zip",
            out / "py" / "manifest.json",
        ):
            assert path.is_file(), path
        html = (out / "index.html").read_text(encoding="utf-8")
        assert 'href="web/style.css"' in html
        assert (out / "web" / "style.css").read_text(encoding="utf-8").strip()
    finally:
        shutil.rmtree(out, ignore_errors=True)


    def run(host, port):
        status, body = _get(host, port, "/api/scenario/ASI04")
        assert status == 200
        payload = json.loads(body)
        assert payload["report"]["risk_category"]["id"] == "ASI04"
        assert payload["report"]["scores"]["status"] == "normative"
        assert payload["report"]["scores"]["aivss"] == 9.5
        assert payload["report"]["decision"]["ssvc"]["decision_table"] == "cisa:DT_BOD2604:1.0.0"

        missing, _ = _get(host, port, "/api/scenario/ASI99")
        assert missing == 404

    _with_server(run)
