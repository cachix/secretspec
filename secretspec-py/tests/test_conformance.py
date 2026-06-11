"""Cross-language conformance: resolve the shared fixtures and assert the SDK
produces the canonical result every other SDK must also produce."""

import json
import pathlib

import pytest

from secretspec import SecretSpec

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "conformance" / "fixtures"


def _canonical(resolved) -> dict:
    secrets = {}
    for name, secret in resolved.secrets.items():
        value = (
            pathlib.Path(secret.path).read_text() if secret.as_path else secret.value
        )
        secrets[name] = {
            "value": value,
            "source": secret.source,
            "as_path": secret.as_path,
        }
    return {
        "profile": resolved.profile,
        "secrets": secrets,
        "missing_required": [],
        "missing_optional": sorted(resolved.missing_optional),
    }


def _canonical_report(report) -> dict:
    return {
        "profile": report.profile,
        "secrets": {
            s.name: {
                "status": s.status,
                "required": s.required,
                "as_path": s.as_path,
                "generated": s.generated,
                "default_applied": s.default_applied,
                # Present-or-not (not the path-dependent value) so the vector is
                # machine-independent yet still catches a dropped source_provider.
                "source_provider": s.source_provider is not None,
            }
            for s in report.secrets
        },
    }


def _fixtures():
    return sorted(p.name for p in FIXTURES.iterdir() if p.is_dir())


def _builder(directory):
    return (
        SecretSpec.builder()
        .with_path(str(directory / "secretspec.toml"))
        .with_provider(f"dotenv://{directory / '.env'}")
        .with_reason("conformance")
    )


@pytest.mark.parametrize("fixture", _fixtures())
def test_conformance(fixture):
    directory = FIXTURES / fixture
    expected = json.loads((directory / "expected.json").read_text())

    resolved = _builder(directory).load()
    try:
        assert _canonical(resolved) == expected
    finally:
        # Remove any as_path temp files this value-carrying resolve materialized,
        # so repeated runs do not accumulate secret files in the temp dir.
        resolved.close()


@pytest.mark.parametrize("fixture", _fixtures())
def test_conformance_no_values(fixture):
    """Under no_values every SDK must emit the same all-null fields map: a
    value-less secret serializes to null, not an empty string."""
    directory = FIXTURES / fixture
    expected = json.loads((directory / "expected_no_values.json").read_text())

    resolved = _builder(directory).with_no_values().load()
    try:
        assert resolved.fields() == expected
    finally:
        resolved.close()


@pytest.mark.parametrize("fixture", _fixtures())
def test_conformance_report(fixture):
    """The value-free report (status + provenance) is identical across SDKs."""
    directory = FIXTURES / fixture
    expected = json.loads((directory / "expected_report.json").read_text())

    report = _builder(directory).report()

    assert _canonical_report(report) == expected
