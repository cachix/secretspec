"""Build a platform-specific ``abi3`` wheel with the Rust resolver linked in.

Project metadata lives in ``pyproject.toml``. This file wires the cffi
out-of-line extension (``secretspec/_build_ffi.py``), which compiles a CPython
extension that statically links ``libsecretspec_ffi.a``. The extension targets
the CPython limited API (``py_limited_api=True``), so one ``cp39-abi3-<platform>``
wheel serves every CPython >= 3.9 on that platform.
"""

from setuptools import setup
from setuptools.dist import Distribution

try:  # setuptools >= 70 vendors bdist_wheel
    from setuptools.command.bdist_wheel import bdist_wheel
except ImportError:  # pragma: no cover - older setuptools
    from wheel.bdist_wheel import bdist_wheel


class BinaryDistribution(Distribution):
    """Marks the distribution as containing a native extension, so the wheel is
    platform-specific rather than ``any``."""

    def has_ext_modules(self) -> bool:
        return True


class PlatformWheel(bdist_wheel):
    def finalize_options(self) -> None:
        # Emit a single abi3 wheel (cp39-abi3-<platform>) for the limited-API
        # extension instead of one wheel per CPython minor version.
        super().finalize_options()
        self.py_limited_api = "cp39"


setup(
    distclass=BinaryDistribution,
    cmdclass={"bdist_wheel": PlatformWheel},
    cffi_modules=["secretspec/_build_ffi.py:ffibuilder"],
)
