# mbedTLS Project Notes

- Last constraint added: `mbedtls_handshake_msg_len_bounds` (TLS handshake message length uint24: 0..16,777,215)
- Key files:
  - `core/constraints.py`
  - `core/parser.py`
  - `core/verify.py`
- Validation run:
  - Project-only check via `get_mbedtls_checks` + `run_check`
  - Result: 7/7 VERIFIED

## Next 2 candidate constraints
1. Handshake message type bounds (`handshake_type` in `mbedtls_ssl_parse_handshake_header`) limited to defined TLS handshake enums.
2. Certificate chain length bounds (`cert_chain_len`) to cap parsed certificate list size and prevent memory exhaustion.
