"""End-to-end test of the typed-codegen pipeline:

    secretspec schema  ->  quicktype  ->  Type.from_dict(resolved.fields())

This proves the schema we emit drives quicktype to a typed class whose
deserializer consumes the runtime SDK's flat fields() map.
"""

import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

from secretspec import SecretSpec

MANIFEST = """
[project]
name = "codegen-test"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "DB", required = true }
LOG_LEVEL = { description = "log", required = false, default = "info" }
SENTRY_DSN = { description = "sentry", required = false }
"""

pytestmark = pytest.mark.skipif(
    shutil.which("npx") is None, reason="npx (for quicktype) not available"
)


def _generate_types(tmp_path: pathlib.Path, name: str):
    manifest = tmp_path / "secretspec.toml"
    manifest.write_text(MANIFEST)

    schema = tmp_path / "schema.json"
    subprocess.run(
        [os.environ["SECRETSPEC_BIN"], "-f", str(manifest), "schema", "-o", str(schema)],
        check=True,
    )

    generated = tmp_path / f"{name}.py"
    subprocess.run(
        [
            "npx",
            "--yes",
            "quicktype",
            "-s",
            "schema",
            str(schema),
            "--top-level",
            "SecretSpec",
            "--lang",
            "python",
            "--python-version",
            "3.7",
            "-o",
            str(generated),
        ],
        check=True,
    )

    spec = importlib.util.spec_from_file_location(name, generated)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)  # also validates the generated syntax
    return module, manifest


def test_quicktype_types_consume_runtime_fields(tmp_path):
    env = tmp_path / ".env"
    env.write_text("DATABASE_URL=postgres://db\n")
    module, manifest = _generate_types(tmp_path, "gen_python")

    resolved = (
        SecretSpec.builder()
        .with_path(str(manifest))
        .with_provider(f"dotenv://{env}")
        .with_reason("codegen test")
        .load()
    )

    # The quicktype-generated, typed class is constructed from the runtime SDK's
    # flat fields() map. Idiomatic snake_case attributes, typed.
    typed = module.SecretSpec.from_dict(resolved.fields())
    assert typed.database_url == "postgres://db"
    assert typed.log_level == "info"  # from default
    assert typed.sentry_dsn is None  # optional, missing
