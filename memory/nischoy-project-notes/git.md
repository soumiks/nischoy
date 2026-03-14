# git project notes

- last_run_utc: 2026-03-14T10:00:00Z
- last_constraint: Object Type Allowed Set (Exclude Reserved 5)
- short_name: git-object-type-allowed-set
- status: added and verified (constraint reports FAIL -> reserved obj_type=5 currently satisfiable)

## key_files
- core/constraints.py
- core/verify.py
- public/git.html

## next_candidate_constraints
1. Ensure `hash_algo` and `hash_rawsz` are consistent pairs: (1 -> 20) or (2 -> 32).
2. Constrain pkt-line special values: allow exact flush/delim/response-end markers (0,1,2) plus payload lengths >=4 and <=65520.
