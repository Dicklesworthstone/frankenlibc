# Sheaf Global-Consistency Proof Note (bd-249m.7)

## Scope
- This artifact covers the checked-in runtime sheaf proxy in `crates/frankenlibc-membrane/src/runtime_math/cohomology.rs`.
- It proves the declared open cover over the current FrankenLibC subsystem surface glues without first-cohomology obstructions in the finite xor-witness model used by the live monitor.
- It does not claim a fully mechanized Grothendieck-topos proof for every future subsystem or controller family.

## Open Cover
We reason over the subsystem cover recorded in `tests/conformance/sheaf_coverage.v1.json`:

- `U_allocator`: allocator provenance, generation, quarantine invariants.
- `U_string`: pointer-bounds and byte-sequence invariants for `mem*`/`str*`.
- `U_stdio`: buffer cursor, flush ordering, and format parser invariants.
- `U_thread`: mutex/TLS/thread-registry invariants.
- `U_math`: libm/fenv numeric-domain and error-reporting invariants.
- `U_signal`: signal-mask, handler installation, and async-control invariants.
- `U_resolver`: resolver request/response and cache-coherency invariants.

The declared overlaps cover the release-critical seams: allocator/string,
string/stdio, allocator/stdio, thread/signal, resolver/thread, and
math/stdio.

## Statement
For the shipped cohomology monitor and declared subsystem cover:

- Locality holds: if two global safety witnesses restrict to the same local
  witnesses on every declared subsystem, they are indistinguishable in the
  finite xor-witness model.
- Gluing holds constructively: pairwise-compatible local witnesses admit a
  unique global witness because every overlap witness is the xor of the two
  section hashes it relates.
- The first Cech cohomology class is trivial on every declared triple overlap:
  `w_ij xor w_jk xor w_ik = 0`.
- The restriction-map tests in
  `crates/frankenlibc-harness/tests/runtime_math_cohomology_cross_family_test.rs`
  and the unit proofs in
  `crates/frankenlibc-membrane/src/runtime_math/cohomology.rs`
  keep the gluing contract replayable in CI.

## Evidence Surface
- Runtime sheaf proxy:
  `crates/frankenlibc-membrane/src/runtime_math/cohomology.rs`
- Open-cover artifact:
  `tests/conformance/sheaf_coverage.v1.json`
- Cross-family overlap gate:
  `scripts/check_runtime_math_cohomology_cross_family.sh`
- Harness integration test:
  `crates/frankenlibc-harness/tests/runtime_math_cohomology_cross_family_test.rs`
- Proof binder entry and traceability snapshot:
  `tests/conformance/proof_obligations_binder.v1.json`
  `tests/conformance/proof_traceability_check.json`

## Current Result
- All declared open-cover sections carry explicit local predicates and source
  anchors.
- All declared pairwise overlaps are checked for witness compatibility.
- The declared triple overlaps have trivial cocycle witnesses in the checked
  xor model, so `H^1(U, F) = 0` for the finite cover captured in the artifact.
- The proof binder now tracks this theorem with concrete evidence artifacts,
  gates, and source references instead of manifest-only metadata.

## Explicit Non-Claims
- No claim is made that every possible future subsystem partition shares the
  same finite cover.
- No claim is made that xor witnesses are a complete substitute for richer
  categorical or homotopical semantics.
- No claim is made that locale/catalog descent or loader namespace gluing is
  closed beyond the declared artifact surface.

## Verification Commands
- `rch exec -- cargo test -p frankenlibc-membrane proof_triple_overlap_cocycle_is_trivial --lib -- --nocapture`
- `rch exec -- cargo test -p frankenlibc-harness --test runtime_math_cohomology_cross_family_test -- --nocapture`
- `bash scripts/check_runtime_math_cohomology_cross_family.sh`
- `bash scripts/check_proof_binder.sh`
