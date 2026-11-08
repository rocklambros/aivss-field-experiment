"""Package aivss_calc for the in-browser (Pyodide) calculator.

The web page downloads this zip and runs the same Python code as the CLI, so
browser results cannot drift from the reference implementation.
"""

from __future__ import annotations

import io
import zipfile
from importlib import metadata
from pathlib import Path
from typing import Any

from .versions import CALCULATOR_VERSION

PYODIDE_VERSION = "314.0.7"
PYODIDE_INDEX_URL = f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VERSION}/full/"
BUNDLE_NAME = "aivss_calc.zip"

PACKAGE_ROOT = Path(__file__).resolve().parent


def package_zip() -> bytes:
    """Return the aivss_calc package (sources and data) as zip bytes."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(PACKAGE_ROOT.rglob("*")):
            if path.is_dir() or "__pycache__" in path.parts:
                continue
            if path.suffix not in {".py", ".json"}:
                continue
            arcname = Path("aivss_calc") / path.relative_to(PACKAGE_ROOT)
            archive.write(path, arcname.as_posix())
    return buffer.getvalue()


def manifest() -> dict[str, Any]:
    """Describe the runtime the page must load, pinned to this build."""
    return {
        "calculator_version": CALCULATOR_VERSION,
        "pyodide_version": PYODIDE_VERSION,
        "pyodide_index_url": PYODIDE_INDEX_URL,
        "packages": [f"cvss=={metadata.version('cvss')}"],
        "bundle": f"py/{BUNDLE_NAME}",
    }
