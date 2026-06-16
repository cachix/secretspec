"""Compile the secretspec cffi extension before the tests import the package.

The SDK now statically links ``libsecretspec_ffi.a`` into a compiled extension
(``secretspec._secretspec_cffi``) rather than dlopening a cdylib, so the
extension must exist before ``import secretspec``. Build the debug archive +
CLI, point the build-time link contract at the debug archive (fast), then
compile the extension in place. Mirrors the Node SDK's "ensure the addon exists"
harness. ``SECRETSPEC_BIN`` (the CLI) is still needed by the codegen test.
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


def _native_libs() -> str:
    note = subprocess.run(
        ["cargo", "rustc", "-q", "-p", "secretspec-ffi", "--crate-type",
         "staticlib", "--", "--print", "native-static-libs"],
        cwd=_REPO_ROOT, capture_output=True, text=True, check=True,
    )
    marker = "native-static-libs: "
    libs = ""
    for line in (note.stderr + note.stdout).splitlines():
        if marker in line:
            libs = line.split(marker, 1)[1].strip()
    return libs


def _ensure_extension_and_bin() -> None:
    subprocess.run(
        ["cargo", "build", "-p", "secretspec-ffi", "-p", "secretspec"],
        cwd=_REPO_ROOT, check=True,
    )
    meta = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=_REPO_ROOT, check=True, capture_output=True, text=True,
    )
    debug = pathlib.Path(json.loads(meta.stdout)["target_directory"]) / "debug"
    os.environ.setdefault("SECRETSPEC_BIN", str(debug / _bin_name()))
    # Point _build_ffi.py at the debug archive (fast) unless a contract is set.
    os.environ.setdefault("SECRETSPEC_FFI_STATICLIB", str(debug / "libsecretspec_ffi.a"))
    os.environ.setdefault("SECRETSPEC_FFI_INCLUDE", str(_REPO_ROOT / "secretspec-ffi" / "include"))
    if "SECRETSPEC_FFI_NATIVE_LIBS" not in os.environ:
        os.environ["SECRETSPEC_FFI_NATIVE_LIBS"] = _native_libs()
    subprocess.run(
        [sys.executable, str(_PKG_DIR / "secretspec" / "_build_ffi.py")],
        cwd=_PKG_DIR, check=True,
    )


_ensure_extension_and_bin()
