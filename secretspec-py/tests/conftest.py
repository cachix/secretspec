"""Build the secretspec-py-native pyo3 extension before the tests import the
package.

``maturin develop`` builds the extension crate (debug, fast) and installs it
in place into the current Python environment, mirroring the Node SDK's
"ensure the addon exists" harness. ``SECRETSPEC_BIN`` (the CLI) is still
needed by the codegen test.
"""

import json
import os
import pathlib
import subprocess
import sys

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PKG_DIR = _REPO_ROOT / "secretspec-py"


def _bin_name() -> str:
    return "secretspec.exe" if sys.platform == "win32" else "secretspec"


def _ensure_extension_and_bin() -> None:
    subprocess.run(["cargo", "build", "-p", "secretspec"], cwd=_REPO_ROOT, check=True)
    meta = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=_REPO_ROOT, check=True, capture_output=True, text=True,
    )
    debug = pathlib.Path(json.loads(meta.stdout)["target_directory"]) / "debug"
    os.environ.setdefault("SECRETSPEC_BIN", str(debug / _bin_name()))
    subprocess.run(["maturin", "develop"], cwd=_PKG_DIR, check=True)


_ensure_extension_and_bin()
