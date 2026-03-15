# openssl - Project Notes

## Constraints (5 total)
1. **dsa_sig_len_bounds** — DER decode length must be non-negative
2. **openssl_evp_key_size_bounds** — EVP key length 1-64 bytes
3. **openssl_bn_num_bits_bounds** — BIGNUM bit count 0-16384
4. **openssl_x509_version_bounds** — X.509 version 0-2
5. **openssl_tls_version_bounds** — TLS wire version 0x0300-0x0304 *(added 2026-03-15)*

## Key Files
- `core/parser.py` — `parse_openssl_tls_version` parser model
- `core/constraints.py` — `openssl_tls_version_bounds` predicate
- `core/verify.py` — `get_openssl_checks()` registration and security rationale
- `public/openssl.html` — regenerated OpenSSL verification report

## Next Candidate Constraints
1. **openssl_record_content_type_bounds** — constrain TLS record content type to known values (20-23) to prevent invalid state-machine dispatch
2. **openssl_cert_chain_depth_bounds** — constrain certificate chain depth (e.g., 0-100) to reduce DoS risk from pathological chain traversal
