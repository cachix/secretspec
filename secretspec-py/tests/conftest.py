"""Ensure the secretspec-ffi cdylib is built and discoverable before tests run.

If SECRETSPEC_FFI_LIB is not already set, build the crate and point the SDK at
the freshly built library in the Cargo target directory.
"""

import json
import os
import pathlib
import subprocess
import sys

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _lib_name() -> str:
    if sys.platform == "darwin":
        return "libsecretspec_ffi.dylib"
    if sys.platform == "win32":
        return "secretspec_ffi.dll"
    return "libsecretspec_ffi.so"


def _bin_name() -> str:
    return "secretspec.exe" if sys.platform == "win32" else "secretspec"


def _ensure_lib() -> None:
    have_lib = bool(os.environ.get("SECRETSPEC_FFI_LIB"))
    have_bin = bool(os.environ.get("SECRETSPEC_BIN"))
    if have_lib and have_bin:
        return

    # Build the cdylib (for the runtime SDK) and the CLI (for codegen tests).
    subprocess.run(
        ["cargo", "build", "-p", "secretspec-ffi", "-p", "secretspec"],
        cwd=_REPO_ROOT,
        check=True,
    )
    meta = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=_REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    debug_dir = pathlib.Path(json.loads(meta.stdout)["target_directory"]) / "debug"
    os.environ.setdefault("SECRETSPEC_FFI_LIB", str(debug_dir / _lib_name()))
    os.environ.setdefault("SECRETSPEC_BIN", str(debug_dir / _bin_name()))


_ensure_lib()
