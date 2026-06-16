"""cffi out-of-line (API mode) build script for the secretspec Python SDK.

Compiles a CPython extension (``secretspec._secretspec_cffi``) that STATICALLY
links the secretspec-ffi archive (``libsecretspec_ffi.a``), so the Rust resolver
is embedded in the extension. There is no separate cdylib to ship in the wheel,
no ``SECRETSPEC_FFI_LIB``, and no runtime dlopen discovery.

The archive and its transitive native deps are taken, in order, from:
  1. the ``SECRETSPEC_FFI_STATICLIB`` / ``SECRETSPEC_FFI_NATIVE_LIBS`` /
     ``SECRETSPEC_FFI_INCLUDE`` environment variables (the build-time link
     contract exported by ``scripts/ci-sdks.sh``); otherwise
  2. a release build produced here with cargo, capturing the native deps from
     ``rustc --print native-static-libs`` (wheel builds, local ``pip install``).

The extension is built against the CPython limited API (``py_limited_api=True``),
so one ``abi3`` wheel serves every CPython >= 3.9 on a given platform.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess

from cffi import FFI

_PKG_DIR = pathlib.Path(__file__).resolve().parent  # secretspec-py/secretspec
_REPO_ROOT = _PKG_DIR.parents[1]  # repository root

# The narrow C ABI. Mirrors secretspec-ffi/include/secretspec.h.
_CDEF = """
    char *secretspec_resolve(const char *request_json);
    void secretspec_free(char *ptr);
    const char *secretspec_abi_version(void);
"""


def _native_libs_from_note(text: str) -> list[str]:
    marker = "native-static-libs: "
    libs: list[str] = []
    for line in text.splitlines():
        if marker in line:
            libs = line.split(marker, 1)[1].split()
    return libs


def _cargo_target_dir() -> pathlib.Path:
    meta = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=_REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return pathlib.Path(json.loads(meta.stdout)["target_directory"])


def _resolve_link_inputs() -> tuple[str, list[str], str]:
    """Return (staticlib_path, native_libs, include_dir)."""
    env_lib = os.environ.get("SECRETSPEC_FFI_STATICLIB")
    env_native = os.environ.get("SECRETSPEC_FFI_NATIVE_LIBS")
    env_include = os.environ.get("SECRETSPEC_FFI_INCLUDE")
    if env_lib and env_native is not None and env_include:
        return env_lib, env_native.split(), env_include

    # No prebuilt contract in the environment: build the release archive and
    # capture its native deps ourselves.
    subprocess.run(
        ["cargo", "build", "-p", "secretspec-ffi", "--release"],
        cwd=_REPO_ROOT,
        check=True,
    )
    note = subprocess.run(
        [
            "cargo",
            "rustc",
            "-q",
            "-p",
            "secretspec-ffi",
            "--release",
            "--crate-type",
            "staticlib",
            "--",
            "--print",
            "native-static-libs",
        ],
        cwd=_REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    native = _native_libs_from_note(note.stderr + note.stdout)
    staticlib = _cargo_target_dir() / "release" / "libsecretspec_ffi.a"
    include = _REPO_ROOT / "secretspec-ffi" / "include"
    return str(staticlib), native, str(include)


_staticlib, _native_libs, _include = _resolve_link_inputs()

ffibuilder = FFI()
ffibuilder.cdef(_CDEF)
ffibuilder.set_source(
    "secretspec._secretspec_cffi",
    '#include "secretspec.h"',
    include_dirs=[_include],
    # Link the whole archive in (the linker pulls the referenced objects); the
    # archive's transitive system libs follow it on the link line.
    extra_objects=[_staticlib],
    extra_link_args=_native_libs,
    py_limited_api=True,
)


if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
