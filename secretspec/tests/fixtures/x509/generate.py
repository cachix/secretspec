"""Regenerate public interoperability fixtures with the OpenSSL CLI."""

from pathlib import Path
import subprocess
import tempfile

OUTPUT = Path(__file__).resolve().parent


def run(*args):
    subprocess.run(
        ["openssl", *map(str, args)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    for name, kind, options in [
        ("p256", "EC", ["-pkeyopt", "ec_paramgen_curve:P-256"]),
        ("p384", "EC", ["-pkeyopt", "ec_paramgen_curve:P-384"]),
        ("p521", "EC", ["-pkeyopt", "ec_paramgen_curve:P-521"]),
        ("rsa", "RSA", ["-pkeyopt", "rsa_keygen_bits:2048"]),
        ("ed25519", "ED25519", []),
    ]:
        key = root / f"{name}.key"
        certificate = root / f"{name}.pem"
        run("genpkey", "-algorithm", kind, *options, "-out", key)
        run(
            "req", "-new", "-x509", "-key", key, "-out", certificate,
            "-subj", "/CN=fixture.example", "-days", "36500",
            "-addext", "subjectAltName=DNS:fixture.example",
        )
        run("x509", "-in", certificate, "-outform", "DER", "-out", OUTPUT / f"{name}.der")
        export = [
            "pkcs12", "-export", "-inkey", key, "-in", certificate,
            "-name", "fixture", "-iter", "100000",
            "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC", "-macalg", "sha256",
        ]
        run(*export, "-passout", "pass:fixture-password", "-out", OUTPUT / f"{name}.pfx")
        if name == "p256":
            run(*export, "-passout", "pass:päss漢字", "-out", OUTPUT / "bmp-password.pfx")
            run(*export, "-passout", "pass:päss🔑", "-out", OUTPUT / "supplementary-password.pfx")
            run(
                *export, "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES",
                "-macalg", "sha1", "-passout", "pass:fixture-password",
                "-out", OUTPUT / "legacy-3des.pfx",
            )

print("Generated OpenSSL interoperability fixtures, including legacy 3DES and Unicode passwords.")
