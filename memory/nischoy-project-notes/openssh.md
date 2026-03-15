# OpenSSH - Project Notes

## Constraints (6 total)
1. **max_authtries_bounds** — auth tries 1-100
2. **channel_id_bounds** — channel ID 0-65535
3. **packet_len_bounds** — packet length 5-262144
4. **key_bits_bounds** — key bit length 1024-16384
5. **padding_len_bounds** — packet padding 4-255 bytes (RFC 4253 §6)
6. **kex_proposal_len_bounds** — KEX proposal string 1-32768 bytes *(added 2026-03-15)*

## Key Files
- `core/constraints.py` — SecurityConstraints static methods
- `core/parser.py` — parse_openssh_* methods
- `core/verify.py` — get_openssh_checks()

## Next Candidate Constraints
1. **openssh_max_sessions_bounds** — MaxSessions config value must be 1-1024; prevents session table exhaustion attacks
2. **openssh_tcp_fwd_port_bounds** — TCP forwarding port must be 1-65535; zero/negative ports cause undefined bind behavior
