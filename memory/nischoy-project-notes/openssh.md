# OpenSSH - Project Notes

## Constraints (5 total)
1. **max_authtries_bounds** — auth tries 1-100
2. **channel_id_bounds** — channel ID 0-65535
3. **packet_len_bounds** — packet length 5-262144
4. **key_bits_bounds** — key bit length 1024-16384
5. **padding_len_bounds** — packet padding 4-255 bytes (RFC 4253 §6) *(added 2026-03-14)*

## Key Files
- `core/constraints.py` — SecurityConstraints static methods
- `core/parser.py` — parse_openssh_* methods
- `core/verify.py` — get_openssh_checks()

## Next Candidate Constraints
1. **openssh_kex_proposal_length_bounds** — Key exchange proposal string length must be 1-32768; oversized proposals cause memory exhaustion during handshake
2. **openssh_max_sessions_bounds** — MaxSessions config value must be 1-1024; prevents session table exhaustion attacks
