"""Build a platform-specific wheel that bundles the secretspec-ffi cdylib.

Project metadata lives in ``pyproject.toml``; this file only (a) forces a
platform (non-pure) wheel so pip installs the right native library per OS/arch,
and (b) tags it ``py3-none-<platform>`` because the package is pure Python apart
from the bundled library, which works on any Python 3.

The native library must be staged into ``secretspec/_lib/`` before building it
(see ``scripts/stage-cdylib.sh``); it is declared as package data in
``pyproject.toml``.
"""

from setuptools import setup
from setuptools.dist import Distribution

try:  # setuptools >= 70 vendors bdist_wheel
    from setuptools.command.bdist_wheel import bdist_wheel
except ImportError:  # pragma: no cover - older setuptools
    from wheel.bdist_wheel import bdist_wheel


class BinaryDistribution(Distribution):
    """Marks the distribution as containing a native library, so the wheel is
    platform-specific rather than ``any``."""

    def has_ext_modules(self) -> bool:
        return True


class PlatformWheel(bdist_wheel):
    def get_tag(self):
        _, _, platform = super().get_tag()
        return "py3", "none", platform


setup(
    distclass=BinaryDistribution,
    cmdclass={"bdist_wheel": PlatformWheel},
)
