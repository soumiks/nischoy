# nginx - Project Notes

## Constraints (7 total)
1. **nginx_field_len_bounds** — HTTP/2 field length must be non-negative
2. **nginx_status_code_bounds** — HTTP status code 100-599
3. **nginx_uri_length_bounds** — request URI length 1-8192
4. **nginx_header_count_bounds** — header count 0-100
5. **nginx_http_minor_version_bounds** — HTTP minor version 0-9
6. **nginx_http_major_version_bounds** — HTTP major version 0-9
7. **nginx_header_name_length_bounds** — header name length 1-1024 *(added 2026-03-15)*

## Key Files
- `core/constraints.py` — `nginx_header_name_length_bounds` and nginx constraint predicates
- `core/parser.py` — `parse_ngx_http_header_name_length` parser model
- `core/verify.py` — `get_nginx_checks()` registration/explanation
- `public/nginx.html` — regenerated nginx verification report

## Next Candidate Constraints
1. **nginx_header_value_length_bounds** — constrain single header value length (e.g., 0-8192) to reduce memory amplification and parser desync risk
2. **nginx_chunk_size_hex_digits_bounds** — constrain Transfer-Encoding chunk-size digit count (1-16 hex digits) to prevent integer overflow in chunk parser
