"""End-to-end check that the in-browser calculator matches the Python results.

Needs Playwright, a Chromium browser, and network access to the Pyodide CDN, so
it only runs when AIVSS_BROWSER_TESTS=1. Set AIVSS_BROWSER_CHANNEL=chrome to
use an installed Google Chrome instead of Playwright's Chromium.
"""

from __future__ import annotations

import os
import threading
from http.server import ThreadingHTTPServer

import pytest

from aivss_calc.demo_server import DemoHandler, _top10_payload

pytestmark = pytest.mark.skipif(
    os.environ.get("AIVSS_BROWSER_TESTS") != "1",
    reason="set AIVSS_BROWSER_TESTS=1 to run browser tests",
)

LOAD_TIMEOUT_MS = 120_000


@pytest.fixture(scope="module")
def base_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as playwright:
        channel = os.environ.get("AIVSS_BROWSER_CHANNEL") or None
        instance = playwright.chromium.launch(channel=channel, headless=True)
        yield instance
        instance.close()


def _open(browser, url, errors):
    page = browser.new_page(viewport={"width": 1280, "height": 900})
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.goto(url)
    page.wait_for_selector("#result:not([hidden])", timeout=LOAD_TIMEOUT_MS)
    return page


def test_presets_match_python(browser, base_url):
    errors: list[str] = []
    page = _open(browser, base_url, errors)
    for row in _top10_payload():
        asi = row["asi"]
        page.click(f".preset:has(.preset-id:text-is('{asi}'))")
        page.wait_for_function(
            "asi => document.querySelector('#preset-status').textContent.startsWith(asi)",
            arg=asi,
        )
        page.wait_for_function(
            "score => document.querySelector('#result-score').textContent === score",
            arg=f"{row['aivss']:.1f}",
        )
        # Consecutive presets can share an AIVSS value, so also wait for the
        # vector and CVSS-BTE of this preset before reading the timelines.
        page.wait_for_function(
            "([v, c]) => document.querySelector('#out-aivss').textContent === v"
            " && document.querySelector('#result-cvss').textContent === c",
            arg=[row["aivss_vector"], f"{row['cvss_bte']:.1f}"],
        )
        assert page.text_content("#result-class") == row["agentic_effect_class"]
        assert page.text_content("#result-u") == str(row["agentic_uplift_u"])
        keys = page.eval_on_selector_all(
            "#decision-result .timeline-key", "els => els.map(e => e.textContent)"
        )
        assert keys == [row["bod_timeline"], row["aivss_recommended_timeline"]], asi
    assert errors == []


def test_share_link_restores_edited_finding(browser, base_url):
    errors: list[str] = []
    page = _open(browser, f"{base_url}?example=ASI06", errors)
    page.locator('#cvss-base .metric-group:has(abbr:text-is("AC"))').locator(
        ".opt", has_text="Low"
    ).click()
    page.wait_for_function(
        "() => document.querySelector('#result-cvss').textContent === '8.7'"
    )
    assert page.text_content("#result-score") == "9.5"
    assert "Custom" in page.text_content("#preset-status")
    shared = page.url
    assert "AC:L" in shared

    reopened = _open(browser, shared, errors)
    reopened.wait_for_function(
        "() => document.querySelector('#result-cvss').textContent === '8.7'"
    )
    assert reopened.text_content("#result-class") == "A2"
    assert errors == []


def test_hints_open_on_hover_click_and_keyboard(browser, base_url):
    errors: list[str] = []
    page = _open(browser, f"{base_url}?example=ASI06", errors)
    tip = page.locator("#hint-tip")
    name = page.locator('#cvss-base .metric-group:has(abbr:text-is("AT")) .metric-name')

    name.hover()
    assert tip.is_visible()
    assert "Conditions of the deployment" in tip.text_content()

    page.mouse.move(5, 5)
    assert tip.is_hidden()

    # A click pins the hint open, which is also what a tap does on a phone.
    name.click()
    page.mouse.move(600, 5)
    assert tip.is_visible()
    page.keyboard.press("Escape")
    assert tip.is_hidden()

    # Option buttons explain themselves on hover but still select on click.
    option = page.locator(
        '#cvss-base .metric-group:has(abbr:text-is("AT")) .opt', has_text="Present"
    )
    option.hover()
    assert tip.is_visible()
    option.click()
    page.wait_for_function(
        "() => document.getElementById('cvss-input').value.includes('AT:P')"
    )
    assert option.get_attribute("aria-pressed") == "true"

    page.keyboard.press("Tab")
    assert tip.is_visible()
    assert errors == []


def test_invalid_pasted_vector_shows_error(browser, base_url):
    errors: list[str] = []
    page = _open(browser, base_url, errors)
    page.fill("#cvss-input", "CVSS:4.0/AV:Q")
    page.click("#vector-form button[type=submit]")
    page.wait_for_selector("#vector-error:not([hidden])")
    assert "Illegal value 'Q'" in page.text_content("#vector-error")
    assert errors == []
