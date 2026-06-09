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


def _fixtures():
    return sorted(p.name for p in FIXTURES.iterdir() if p.is_dir())


@pytest.mark.parametrize("fixture", _fixtures())
def test_conformance(fixture):
    directory = FIXTURES / fixture
    expected = json.loads((directory / "expected.json").read_text())

    resolved = (
        SecretSpec.builder()
        .with_path(str(directory / "secretspec.toml"))
        .with_provider(f"dotenv://{directory / '.env'}")
        .with_reason("conformance")
        .load()
    )

    assert _canonical(resolved) == expected
