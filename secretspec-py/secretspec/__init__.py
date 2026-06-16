"""SecretSpec Python SDK.

A thin client over the ``secretspec-ffi`` C ABI. Resolution (providers, chains,
profiles, generation, ``as_path``) happens entirely in the Rust core; this
package marshals a JSON request to ``secretspec_resolve``, parses the response
envelope, and exposes it with the same vocabulary as the Rust derive crate
(a builder with ``with_provider``/``with_profile``/``with_reason`` and ``load``,
returning a ``Resolved`` with ``.secrets``/``.provider``/``.profile``).

The Rust resolver is statically linked into a compiled CPython extension
(``secretspec._secretspec_cffi``, built by ``_build_ffi.py`` via cffi API mode),
so there is no separate library to locate, no ``SECRETSPEC_FFI_LIB``, and no
runtime dlopen.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

# The compiled extension statically embeds the secretspec-ffi C ABI. ``_lib``
# exposes secretspec_resolve / secretspec_free / secretspec_abi_version; ``_ffi``
# provides the string/NULL helpers.
from secretspec._secretspec_cffi import ffi as _ffi, lib as _lib

# Response wire-format version this SDK understands. Tracks secretspec-ffi's
# RESOLVE_SCHEMA_VERSION; a mismatch means the loaded library is incompatible.
_RESOLVE_SCHEMA_VERSION = 1

# Wire-format version of the value-free report. Tracks secretspec's
# RESOLUTION_REPORT_SCHEMA_VERSION.
_REPORT_SCHEMA_VERSION = 1

__all__ = [
    "SecretSpec",
    "Resolved",
    "ResolvedSecret",
    "Report",
    "SecretReport",
    "SecretSpecError",
    "MissingRequiredError",
    "resolve",
    "report",
    "abi_version",
]

class SecretSpecError(Exception):
    """A resolution call failed (bad manifest, provider error, reason policy)."""

    def __init__(self, kind: str, message: str):
        super().__init__(f"{message} (kind: {kind})")
        self.kind = kind
        self.message = message


class MissingRequiredError(SecretSpecError):
    """One or more required secrets were not found anywhere."""

    def __init__(self, missing: list[str]):
        super().__init__(
            "missing_required",
            "missing required secret(s): " + ", ".join(missing),
        )
        self.missing = missing


@dataclass(frozen=True)
class ResolvedSecret:
    """One resolved secret. Exactly one of ``value`` / ``path`` is set."""

    value: Optional[str]
    path: Optional[str]
    as_path: bool
    source: str
    source_provider: Optional[str]

    @property
    def get(self) -> Optional[str]:
        """The usable string: the file path for ``as_path`` secrets, else the value."""
        return self.path if self.as_path else self.value


@dataclass(frozen=True)
class Resolved:
    """A successful resolution, mirroring the Rust ``Resolved`` wrapper."""

    provider: str
    profile: str
    secrets: dict[str, ResolvedSecret]
    missing_optional: list[str] = field(default_factory=list)

    def set_as_env(self) -> None:
        """Export each resolved secret into ``os.environ`` by its declared name."""
        for name, secret in self.secrets.items():
            usable = secret.get
            if usable is not None:
                os.environ[name] = usable

    def fields(self) -> dict[str, Optional[str]]:
        """Flat ``{SECRET_NAME: value}`` map (the file path for ``as_path``).

        A secret with no usable value (e.g. under ``no_values``) maps to
        ``None``, matching the null the other SDKs emit.

        This is the input for a quicktype-generated deserializer: feed it to the
        generated type's ``from_dict`` to get a typed object. See
        ``secretspec schema``.
        """
        return {name: secret.get for name, secret in self.secrets.items()}

    def close(self) -> None:
        """Remove the temp files backing any ``as_path`` secrets in this result.

        The resolver persists those files (mode 0400) so their paths stay valid
        after resolve returns; the caller owns their lifetime. Call ``close()``
        (or use this object as a context manager) when done so secret files do
        not accumulate in the temp dir. A file already gone is not an error.
        """
        for secret in self.secrets.values():
            if secret.as_path and secret.path is not None:
                try:
                    os.remove(secret.path)
                except FileNotFoundError:
                    pass

    def __enter__(self) -> "Resolved":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@dataclass(frozen=True)
class SecretReport:
    """Value-free resolution outcome for one declared secret: how it would
    resolve and from where, never the value itself."""

    name: str
    status: str  # "resolved" | "missing_required" | "missing_optional"
    required: bool
    source_provider: Optional[str]
    default_applied: bool
    generated: bool
    as_path: bool


@dataclass(frozen=True)
class Report:
    """A value-free resolution snapshot. Unlike :class:`Resolved`, a missing
    required secret is a ``missing_required`` status here, not an error, so a
    report describes a profile even when its secrets are not all available."""

    provider: str
    profile: str
    secrets: list[SecretReport]


def abi_version() -> str:
    """The ABI version reported by the statically linked library."""
    ptr = _lib.secretspec_abi_version()
    return _ffi.string(ptr).decode()


def _resolve_envelope(request: dict) -> dict:
    payload = json.dumps(request).encode("utf-8")
    ptr = _lib.secretspec_resolve(payload)
    if ptr == _ffi.NULL:
        raise SecretSpecError("ffi", "secretspec_resolve returned null")
    try:
        raw = _ffi.string(ptr).decode("utf-8")
    finally:
        _lib.secretspec_free(ptr)
    return json.loads(raw)


def _resolve_response(request: dict) -> dict:
    envelope = _resolve_envelope(request)
    if not envelope.get("ok", False):
        err = envelope.get("error", {})
        raise SecretSpecError(err.get("kind", "unknown"), err.get("message", ""))
    response = envelope.get("response")
    if response is None:
        raise SecretSpecError("ffi", "secretspec_resolve reported ok with no response")
    version = response.get("schema_version")
    if version != _RESOLVE_SCHEMA_VERSION:
        raise SecretSpecError(
            "version",
            f"unsupported resolve schema version {version} (expected "
            f"{_RESOLVE_SCHEMA_VERSION}); the secretspec-ffi library and this SDK "
            "are out of sync",
        )
    return response


def _report_response(request: dict) -> dict:
    envelope = _resolve_envelope(request)
    if not envelope.get("ok", False):
        err = envelope.get("error", {})
        raise SecretSpecError(err.get("kind", "unknown"), err.get("message", ""))
    response = envelope.get("response")
    if response is None:
        raise SecretSpecError("ffi", "secretspec_resolve reported ok with no response")
    version = response.get("schema_version")
    if version != _REPORT_SCHEMA_VERSION:
        raise SecretSpecError(
            "version",
            f"unsupported report schema version {version} (expected "
            f"{_REPORT_SCHEMA_VERSION}); the secretspec-ffi library and this SDK "
            "are out of sync",
        )
    return response


def resolve(
    *,
    path: Optional[str] = None,
    provider: Optional[str] = None,
    profile: Optional[str] = None,
    reason: Optional[str] = None,
) -> Resolved:
    """Resolve secrets and return a :class:`Resolved`.

    Raises :class:`MissingRequiredError` if a required secret is missing, and
    :class:`SecretSpecError` for any other failure.
    """
    return SecretSpec.builder().with_path(path).with_provider(provider).with_profile(
        profile
    ).with_reason(reason).load()


def report(
    *,
    path: Optional[str] = None,
    provider: Optional[str] = None,
    profile: Optional[str] = None,
    reason: Optional[str] = None,
) -> Report:
    """Resolve a value-free :class:`Report` (the inventory/preflight view).

    Unlike :func:`resolve`, never raises :class:`MissingRequiredError`: a missing
    required secret appears as a :class:`SecretReport` with status
    ``"missing_required"``.
    """
    return SecretSpec.builder().with_path(path).with_provider(provider).with_profile(
        profile
    ).with_reason(reason).report()


class SecretSpec:
    """Entry point mirroring the derive crate's ``SecretSpec::builder()``."""

    @staticmethod
    def builder() -> "_Builder":
        return _Builder()


class _Builder:
    def __init__(self) -> None:
        self._request: dict = {}

    def with_path(self, path: Optional[str]) -> "_Builder":
        if path is not None:
            self._request["path"] = path
        return self

    def with_provider(self, provider: Optional[str]) -> "_Builder":
        if provider is not None:
            self._request["provider"] = provider
        return self

    def with_profile(self, profile: Optional[str]) -> "_Builder":
        if profile is not None:
            self._request["profile"] = profile
        return self

    def with_reason(self, reason: Optional[str]) -> "_Builder":
        if reason is not None:
            self._request["reason"] = reason
        return self

    def with_no_values(self, no_values: bool = True) -> "_Builder":
        """Omit secret values, returning only structure and provenance."""
        self._request["no_values"] = no_values
        return self

    def load(self) -> Resolved:
        response = _resolve_response(self._request)

        missing_required = response.get("missing_required", [])
        if missing_required:
            raise MissingRequiredError(missing_required)

        secrets = {
            name: ResolvedSecret(
                value=entry.get("value"),
                path=entry.get("path"),
                as_path=entry.get("as_path", False),
                source=entry.get("source", ""),
                source_provider=entry.get("source_provider"),
            )
            for name, entry in response.get("secrets", {}).items()
        }
        return Resolved(
            provider=response["provider"],
            profile=response["profile"],
            secrets=secrets,
            missing_optional=response.get("missing_optional", []),
        )

    def report(self) -> Report:
        """Resolve a value-free :class:`Report` (the inventory/preflight view).

        Unlike :meth:`load`, never raises :class:`MissingRequiredError`: a missing
        required secret appears as a :class:`SecretReport` with status
        ``"missing_required"``.
        """
        request = dict(self._request)
        request["mode"] = "report"
        response = _report_response(request)
        secrets = [
            SecretReport(
                name=s["name"],
                status=s["status"],
                required=s.get("required", False),
                source_provider=s.get("source_provider"),
                default_applied=s.get("default_applied", False),
                generated=s.get("generated", False),
                as_path=s.get("as_path", False),
            )
            for s in response.get("secrets", [])
        ]
        return Report(
            provider=response["provider"],
            profile=response["profile"],
            secrets=secrets,
        )
