# Nischoy Core — Formal Verification Engine

Generic tooling for parsing C code, converting to SMT2, and verifying security constraints.

## Components

- **parser.py** — C code AST parser. Extracts security-critical code paths into an intermediate representation.
- **converter.py** — AST-to-Z3 converter. Translates the IR into Z3 solver expressions. Language-agnostic.
- **constraints.py** — Decoupled security constraints. The invariants we want to prove. Lives separately from the code being verified (supply chain isolation).
- **verify.py** — Runner. Orchestrates parsing → conversion → constraint checking → HTML output.

## Usage

```bash
pip install -r requirements.txt
python verify.py
```

Results are written to `../public/results.html`.
