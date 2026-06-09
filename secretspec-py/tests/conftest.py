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


def _ensure_lib() -> None:
    if os.environ.get("SECRETSPEC_FFI_LIB"):
        return

    subprocess.run(
        ["cargo", "build", "-p", "secretspec-ffi"],
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
    target_dir = pathlib.Path(json.loads(meta.stdout)["target_directory"])
    os.environ["SECRETSPEC_FFI_LIB"] = str(target_dir / "debug" / _lib_name())


_ensure_lib()
