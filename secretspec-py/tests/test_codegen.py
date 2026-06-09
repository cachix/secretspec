"""End-to-end test of `secretspec codegen --lang python`.

Generates a typed module from a manifest, imports it, and resolves through the
generated accessors, proving the IR-driven codegen produces working code on top
of the runtime SDK.
"""

import importlib.util
import os
import pathlib
import subprocess
import sys

MANIFEST = """
[project]
name = "codegen-test"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "DB", required = true }
LOG_LEVEL = { description = "log", required = false, default = "info" }
SENTRY_DSN = { description = "sentry", required = false }

[profiles.production]
DATABASE_URL = { description = "DB", required = true }
TLS_CERT = { description = "cert", required = true, as_path = true }
"""


def _generate(tmp_path: pathlib.Path, name: str = "generated"):
    manifest = tmp_path / "secretspec.toml"
    manifest.write_text(MANIFEST)
    out = tmp_path / f"{name}.py"
    subprocess.run(
        [
            os.environ["SECRETSPEC_BIN"],
            "-f",
            str(manifest),
            "codegen",
            "--lang",
            "python",
            "-o",
            str(out),
        ],
        check=True,
    )
    spec = importlib.util.spec_from_file_location(name, out)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # so the module resolves its own references
    spec.loader.exec_module(module)  # also validates the generated syntax
    return module, manifest


def test_generated_union_resolves_with_typed_attributes(tmp_path):
    env = tmp_path / ".env"
    env.write_text("DATABASE_URL=postgres://db\n")
    module, manifest = _generate(tmp_path, "gen_union")

    secrets = module.SecretSpec.load(
        provider=f"dotenv://{env}",
        reason="codegen test",
        path=str(manifest),
    )

    # Typed snake_case attributes mirror the derive crate, idiomatic for Python.
    assert secrets.database_url == "postgres://db"
    assert secrets.log_level == "info"  # from default
    assert secrets.sentry_dsn is None  # optional, missing


def test_generated_profile_class_pins_profile_and_paths(tmp_path):
    env = tmp_path / ".env"
    env.write_text("DATABASE_URL=postgres://prod\nTLS_CERT=----cert----\n")
    module, manifest = _generate(tmp_path, "gen_profile")

    prod = module.ProductionSecrets.load(
        provider=f"dotenv://{env}",
        reason="codegen test",
        path=str(manifest),
    )

    assert prod.database_url == "postgres://prod"
    # as_path field is exposed as a readable file path.
    assert pathlib.Path(prod.tls_cert).read_text() == "----cert----"
