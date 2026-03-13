# zlib constraint notes

- Last constraint added: **Deflate Dictionary Length Fits uint16** (`deflate_dict_length_uint16_fit`)
- Rationale: ensures `dictLength` in `deflateSetDictionary` cannot exceed 16-bit copy-counter range (65535), reducing integer truncation risk in downstream copy loops.

## Key files
- `core/constraints.py`
- `core/verify.py`
- `public/zlib.html`

## Next 2 candidate constraints
1. `inflate_window_bits_wrapper_flags_bounds`: verify raw `windowBits` wrapper flag combinations stay within accepted zlib encoding modes before normalization.
2. `deflate_level_bounds`: constrain compression `level` argument to valid range (0..9 plus zlib sentinel/default mode) in `deflateInit2_` path.
