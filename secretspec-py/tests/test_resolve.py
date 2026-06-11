"""Exercise the Python SDK end to end against the real C ABI."""

import pathlib

import pytest

from secretspec import (
    MissingRequiredError,
    SecretSpec,
    SecretSpecError,
    abi_version,
)

MANIFEST = """
[project]
name = "py-test"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "DB", required = true }
LOG_LEVEL = { description = "log", required = false, default = "info" }
SENTRY_DSN = { description = "sentry", required = false }
"""


def _project(tmp_path: pathlib.Path, dotenv: str) -> tuple[str, str]:
    manifest_path = tmp_path / "secretspec.toml"
    env_path = tmp_path / ".env"
    manifest_path.write_text(MANIFEST)
    env_path.write_text(dotenv)
    return str(manifest_path), f"dotenv://{env_path}"


def test_abi_version_nonempty():
    assert abi_version()


def test_load_returns_values_and_provenance(tmp_path):
    manifest, provider = _project(tmp_path, "DATABASE_URL=postgres://db\n")

    resolved = (
        SecretSpec.builder()
        .with_path(manifest)
        .with_provider(provider)
        .with_reason("py test")
        .load()
    )

    assert resolved.profile == "default"
    db = resolved.secrets["DATABASE_URL"]
    assert db.get == "postgres://db"
    assert db.source == "provider"
    assert db.source_provider is not None

    log = resolved.secrets["LOG_LEVEL"]
    assert log.get == "info"
    assert log.source == "default"

    assert resolved.missing_optional == ["SENTRY_DSN"]
    assert "SENTRY_DSN" not in resolved.secrets


def test_set_as_env(tmp_path, monkeypatch):
    manifest, provider = _project(tmp_path, "DATABASE_URL=postgres://db\n")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    resolved = (
        SecretSpec.builder()
        .with_path(manifest)
        .with_provider(provider)
        .with_reason("py test")
        .load()
    )
    resolved.set_as_env()

    import os

    assert os.environ["DATABASE_URL"] == "postgres://db"


def test_missing_required_raises(tmp_path):
    manifest, provider = _project(tmp_path, "")  # DATABASE_URL absent

    with pytest.raises(MissingRequiredError) as exc:
        SecretSpec.builder().with_path(manifest).with_provider(provider).with_reason(
            "py test"
        ).load()

    assert "DATABASE_URL" in exc.value.missing


def test_as_path_returns_readable_file(tmp_path):
    manifest_path = tmp_path / "secretspec.toml"
    env_path = tmp_path / ".env"
    manifest_path.write_text(
        """
[project]
name = "py-test"
revision = "1.0"

[profiles.default]
TLS_CERT = { description = "cert", required = true, as_path = true }
"""
    )
    env_path.write_text("TLS_CERT=----cert-bytes----\n")

    resolved = (
        SecretSpec.builder()
        .with_path(str(manifest_path))
        .with_provider(f"dotenv://{env_path}")
        .with_reason("py test")
        .load()
    )

    try:
        cert = resolved.secrets["TLS_CERT"]
        assert cert.as_path
        assert cert.value is None
        assert pathlib.Path(cert.get).read_text() == "----cert-bytes----"
    finally:
        # as_path materializes a 0400 temp file the caller owns; remove it so
        # the test leaves no secret-bearing file behind in the temp dir.
        resolved.close()


def test_invalid_manifest_raises_secretspec_error(tmp_path):
    with pytest.raises(SecretSpecError) as exc:
        SecretSpec.builder().with_path(
            "/definitely/does/not/exist/secretspec.toml"
        ).with_reason("py test").load()

    assert not isinstance(exc.value, MissingRequiredError)
    assert exc.value.kind
