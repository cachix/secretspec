#!/usr/bin/env python3
"""Register a throwaway Bitwarden account on a local Vaultwarden server.

The official `bw` CLI has no `register` command, so CI needs this to
bootstrap a fixture account before `bw login`. Implements the client-side
crypto of Bitwarden registration (PBKDF2 master key, HKDF stretching,
AES-CBC-256+HMAC-SHA256 EncString, RSA keypair) with the `cryptography`
package as the only non-stdlib dependency.

It can also create an organization, which the CLI likewise cannot do (`bw
create` handles org-collections but not the organization itself). Collections
*can* be made with `bw create org-collection` once the organization exists, so
this only has to cover the one gap.

Usage:
    # register the fixture account
    vaultwarden_bootstrap.py --server http://localhost:18087 \
        --email ci-fixture@example.test --password fixture-master-password

    # create an organization in it, printing the new organization's UUID
    vaultwarden_bootstrap.py --server http://localhost:18087 \
        --email ci-fixture@example.test --password fixture-master-password \
        --create-org "SecretSpec CI"

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
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
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


def enc_string_type4(plaintext: bytes, public_key_der: bytes) -> str:
    """Bitwarden EncString type 4: Rsa2048_OaepSha1_B64 -> '4.ct'.

    How an organization's symmetric key is wrapped for a user: encrypted to
    that user's RSA public key so their private key can unwrap it. SHA-1 is not
    a choice here — it is the OAEP digest Bitwarden clients expect for type 4.
    """
    public_key = serialization.load_der_public_key(public_key_der)
    ct = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    return f"4.{b64(ct)}"


def master_password_hash(email: str, password: str) -> str:
    """The hash sent as the password to both register and token endpoints."""
    master_key = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), email.strip().lower().encode(), KDF_ITERATIONS, 32
    )
    return b64(hashlib.pbkdf2_hmac("sha256", master_key, password.encode(), 1, 32))


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


# The harness fronts vaultwarden with a self-signed internal cert; this tool
# only ever talks to a local disposable server, so skip verification.
SSL_CTX = ssl._create_unverified_context()


def post(url: str, data: bytes, headers: dict) -> tuple[int, str]:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=SSL_CTX) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def get(url: str, headers: dict) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, context=SSL_CTX) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def register(server: str, email: str, password: str) -> int:
    payload = build_register_payload(email, password)
    status, body = post(
        f"{server}/identity/accounts/register",
        json.dumps(payload).encode(),
        {"Content-Type": "application/json"},
    )
    if 200 <= status < 300:
        print(f"registered: HTTP {status}")
        return 0
    if status == 400 and "already" in body.lower():
        print("account already exists — OK")
        return 0
    print(f"register failed: HTTP {status}\n{body[:500]}", file=sys.stderr)
    return 1


def access_token(server: str, email: str, password: str) -> str:
    """Password-grant token for the API, using the same hash as registration."""
    form = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "username": email.strip().lower(),
            "password": master_password_hash(email, password),
            "scope": "api offline_access",
            "client_id": "cli",
            "deviceType": "8",  # UnknownBrowser; vaultwarden only records it
            "deviceIdentifier": str(uuid.uuid4()),
            "deviceName": "secretspec-ci",
        }
    ).encode()
    status, body = post(
        f"{server}/identity/connect/token",
        form,
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    if not 200 <= status < 300:
        raise SystemExit(f"token request failed: HTTP {status}\n{body[:500]}")
    return json.loads(body)["access_token"]


def user_public_key(server: str, token: str) -> bytes:
    """The account's RSA public key, which wraps the new organization's key.

    Read back from the server rather than kept from registration, so creating
    an organization works against an account that already exists.
    """
    status, body = get(
        f"{server}/api/accounts/profile", {"Authorization": f"Bearer {token}"}
    )
    if not 200 <= status < 300:
        raise SystemExit(f"profile request failed: HTTP {status}\n{body[:500]}")
    profile = json.loads(body)
    # Vaultwarden has moved this between the top level and a nested "keys"
    # object across versions, and casing has varied too.
    public_key = (
        profile.get("publicKey")
        or profile.get("PublicKey")
        or (profile.get("keys") or profile.get("Keys") or {}).get("publicKey")
        or (profile.get("keys") or profile.get("Keys") or {}).get("PublicKey")
    )
    if not public_key:
        raise SystemExit(f"no publicKey in profile response: {body[:500]}")
    return base64.b64decode(public_key)


def create_org(
    server: str, token: str, public_key_der: bytes, name: str, collection_name: str
) -> str:
    """Creates an organization and returns its UUID.

    The organization gets its own symmetric key and RSA keypair. The symmetric
    key is wrapped to the *user's* public key so the creating account can
    unwrap it; the organization's own private key and its default collection
    name are wrapped with the organization's symmetric key.
    """
    org_key = os.urandom(64)  # 32 enc + 32 mac
    org_enc, org_mac = org_key[:32], org_key[32:]

    org_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    org_private_der = org_rsa.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    org_public_der = org_rsa.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {
        "name": name,
        "billingEmail": "ci-fixture@example.test",
        "collectionName": enc_string_type2(collection_name.encode(), org_enc, org_mac),
        "key": enc_string_type4(org_key, public_key_der),
        "keys": {
            "publicKey": b64(org_public_der),
            "encryptedPrivateKey": enc_string_type2(
                org_private_der, org_enc, org_mac
            ),
        },
        "planType": 0,  # Free; vaultwarden ignores billing entirely
    }

    status, body = post(
        f"{server}/api/organizations",
        json.dumps(payload).encode(),
        {"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    if not 200 <= status < 300:
        raise SystemExit(f"organization creation failed: HTTP {status}\n{body[:800]}")

    created = json.loads(body)
    org_id = created.get("id") or created.get("Id")
    if not org_id:
        raise SystemExit(f"no organization id in response: {body[:500]}")
    return org_id


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument(
        "--create-org",
        metavar="NAME",
        help="create an organization instead of registering; prints its UUID",
    )
    ap.add_argument(
        "--collection-name",
        default="Default Collection",
        help="name of the organization's initial collection",
    )
    args = ap.parse_args()
    server = args.server.rstrip("/")

    if not args.create_org:
        return register(server, args.email, args.password)

    token = access_token(server, args.email, args.password)
    public_key = user_public_key(server, token)
    org_id = create_org(
        server, token, public_key, args.create_org, args.collection_name
    )
    # stdout is the org id alone so the harness can capture it directly.
    print(org_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
