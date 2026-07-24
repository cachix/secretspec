#!/usr/bin/env python3
"""Register a throwaway Bitwarden account on a local Vaultwarden server.

The official `bw` CLI has no `register` command, so CI needs this to
bootstrap a fixture account before `bw login`. Implements the client-side
crypto of Bitwarden registration (PBKDF2 master key, HKDF stretching,
AES-CBC-256+HMAC-SHA256 EncString, RSA keypair) with the `cryptography`
package as the only non-stdlib dependency.

Usage:
    vaultwarden_bootstrap.py --server http://localhost:18087 \
        --email ci-fixture@example.test --password fixture-master-password

Exits 0 on success (account created or already exists), non-zero otherwise.
These credentials are committable test fixtures, not secrets: the server is
local and disposable.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KDF_PBKDF2 = 0
KDF_ITERATIONS = 600_000


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 expand step only (Bitwarden stretches the master key this way)."""
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def enc_string_type2(plaintext: bytes, enc_key: bytes, mac_key: bytes) -> str:
    """Bitwarden EncString type 2: AesCbc256_HmacSha256_B64 -> '2.iv|ct|mac'."""
    iv = os.urandom(16)
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len]) * pad_len
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def build_register_payload(email: str, password: str) -> dict:
    email = email.strip().lower()
    master_key = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), email.encode(), KDF_ITERATIONS, 32
    )
    master_password_hash = b64(
        hashlib.pbkdf2_hmac("sha256", master_key, password.encode(), 1, 32)
    )
    stretched_enc = hkdf_expand_sha256(master_key, b"enc")
    stretched_mac = hkdf_expand_sha256(master_key, b"mac")

    sym_key = os.urandom(64)  # 32 enc + 32 mac
    protected_sym_key = enc_string_type2(sym_key, stretched_enc, stretched_mac)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_der = rsa_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_der = rsa_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    protected_private_key = enc_string_type2(private_der, sym_key[:32], sym_key[32:])

    return {
        "email": email,
        "name": "CI Fixture",
        "masterPasswordHash": master_password_hash,
        "masterPasswordHint": None,
        "key": protected_sym_key,
        "kdf": KDF_PBKDF2,
        "kdfIterations": KDF_ITERATIONS,
        "keys": {
            "publicKey": b64(public_der),
            "encryptedPrivateKey": protected_private_key,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    payload = build_register_payload(args.email, args.password)
    req = urllib.request.Request(
        f"{args.server.rstrip('/')}/identity/accounts/register",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # The harness fronts vaultwarden with a self-signed internal cert; this
    # tool only ever talks to a local disposable server, so skip verification.
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            print(f"registered: HTTP {resp.status}")
            return 0
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        if e.code == 400 and "already" in body.lower():
            print("account already exists — OK")
            return 0
        print(f"register failed: HTTP {e.code}\n{body[:500]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
