# Galois Connection + Monotonic Safety + Allocation-Integrity Bounds (bd-34s.3)

## Scope
- This artifact covers the membrane-foundation theorems assigned to `bd-34s.3`.
- Covered proof surfaces:
  - Galois connection between the C-facing pointer abstraction and the richer safety-state model.
  - Monotonic safety-lattice behavior under new information.
  - Allocation-integrity bounds for fingerprints, canaries, and generation counters.

## Theorem Bundle
### 1. Galois Connection
For every live pointer classification in the declared membrane domain:

`gamma(alpha(c)) >= c`

Operationally, valid requests are never denied by the abstraction/concretization round-trip, and oversize live-pointer requests are healed rather than rejected.

### 2. Monotonic Safety
The safety lattice satisfies the required algebra:
- `join` is commutative,
- `join` is associative,
- `join` is idempotent,
- `join(a, b)` never increases permissiveness relative to either input.

This is the formal statement behind the project invariant that new evidence only tightens safety.

### 3. Allocation-Integrity Bounds
- Fingerprint collision resistance is modeled with a 64-bit keyed hash, giving a targeted forgery bound of `<= 2^-64`.
- Generation changes force hash changes across tracked allocations, giving the tracked UAF detection story its `P = 1` claim inside the declared arena model.
- Canary verification detects every enumerated single-byte corruption in the checked proof surface, and the keyed 64-bit canary model supports the documented `<= 2^-64` undetected-corruption bound for random-forgery style attacks.

## Machine-Checked Traceability Anchors
- `crates/frankenlibc-membrane/src/galois.rs:278`
  Galois round-trip proof over live-pointer requests.
- `crates/frankenlibc-membrane/src/galois.rs:352`
  null-preservation proof for the abstraction function.
- `crates/frankenlibc-membrane/src/lattice.rs:129`
  join commutativity.
- `crates/frankenlibc-membrane/src/lattice.rs:151`
  join associativity.
- `crates/frankenlibc-membrane/src/lattice.rs:175`
  join idempotence.
- `crates/frankenlibc-membrane/src/lattice.rs:428`
  monotonicity proof: join never increases permissiveness.
- `crates/frankenlibc-membrane/src/lattice.rs:493`
  permission-consistency proof for read/write projections.
- `crates/frankenlibc-membrane/src/fingerprint.rs:308`
  empirical collision-resistance support for the 64-bit fingerprint model.
- `crates/frankenlibc-membrane/src/fingerprint.rs:351`
  generation-change proof underlying the tracked UAF story.
- `crates/frankenlibc-membrane/src/fingerprint.rs:380`
  single-bit fingerprint sensitivity proof.
- `crates/frankenlibc-membrane/src/fingerprint.rs:414`
  exhaustive single-byte canary corruption detection proof.
- `crates/frankenlibc-membrane/src/fingerprint.rs:445`
  fingerprint serialization bijection proof.
- `crates/frankenlibc-membrane/src/arena.rs:731`
  strict generation monotonicity across alloc/free cycles.
- `crates/frankenlibc-membrane/src/arena.rs:769`
  double-free detection proof.

## Evidence and Reproduction
- Galois theorem:
  `rch exec -- cargo test -p frankenlibc-membrane proof_galois_connection_valid_operations_never_denied --lib -- --nocapture`
- Monotonic safety theorem:
  `rch exec -- cargo test -p frankenlibc-membrane proof_join_never_increases_permissiveness --lib -- --nocapture`
- Allocation-integrity bounds:
  `rch exec -- cargo test -p frankenlibc-membrane proof_generation_change_always_changes_hash --lib -- --nocapture`
  `rch exec -- cargo test -p frankenlibc-membrane proof_canary_detects_all_single_byte_corruptions --lib -- --nocapture`
- Binder gate:
  `bash scripts/check_proof_binder.sh`
- Traceability refresh:
  `python3 scripts/gentoo/proof_binder_validator.py --dry-run --format json --no-hashes --output tests/conformance/proof_traceability_check.json`

## Current Status
- Status: binder-wired for `bd-34s.3`.
- Completed in this phase: added explicit proof-note coverage and binder ownership for the Galois, monotonic-safety, and probability-bound theorem bundle.
- Remaining after bead closure: stronger mechanization beyond the checked Rust proof surface (for example, Lean/Coq/Kani) if and when the project chooses to raise the proof-language bar.
