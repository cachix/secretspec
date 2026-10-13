# OpenSSL interoperability fixtures

These archives contain disposable test keys and self-signed certificates for
`fixture.example`. Their passwords are public test data. Generated with
OpenSSL 3.6.4 using `python3 generate.py`; OpenSSL is needed only to regenerate
fixtures, not to build or run the Rust tests.

The RSA, P-256, P-384, P-521, and Ed25519 archives use password
`fixture-password`, AES-256-CBC with PBKDF2/HMAC-SHA-256, a SHA-256 MAC, and
100,000 iterations. The legacy archive uses 3DES/SHA-1. The Unicode archives
use `päss漢字` and `päss🔑`. The `.der` files record the expected leaf certificate.
Certificates expire in 2126 so fixture lifetime does not drive routine updates.

Regeneration replaces every fixture with newly generated keys and certificates.
The tests compare each archive with its corresponding certificate rather than
assuming a particular random key or serial number.
