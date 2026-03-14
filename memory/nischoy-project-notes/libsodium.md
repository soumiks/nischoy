# libsodium

- Last constraint added: **Curve25519 Box Plaintext Length Non-Negative**
- Short name: `crypto-box-plaintext-nonnegative`
- Why it matters: proves `clen - crypto_box_MACBYTES` cannot underflow before decrypt path derives plaintext length.

## Key files
- `core/verify.py` (libsodium check registry)
- `core/constraints.py` (SMT violation predicate)
- `public/libsodium.html` (verification output)

## Next 2 candidate constraints
1. `crypto_secretbox_open_detached` MAC length consistency (`maclen == crypto_secretbox_MACBYTES`) to prevent detached-tag truncation acceptance.
2. `crypto_kdf_blake2b_derive_from_key` context domain check (8-byte context must exclude all-zero or reserved namespace values to avoid cross-domain key reuse).
