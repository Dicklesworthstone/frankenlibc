# SOS Barrier Soundness + Barrier Invariance (bd-34s.2)

## Scope
This note documents soundness obligations and implemented checks for the SOS barrier certificates used by FrankenLibC runtime membrane policies.

Implemented certificate families:
- `fragmentation`
- `thread_safety`
- `size_class`

Source of runtime evaluators:
- `crates/frankenlibc-membrane/src/runtime_math/sos_barrier.rs`

Source of build-time artifact generation and verification:
- `crates/frankenlibc-membrane/build.rs`

## Model
For each certificate family, offline synthesis emits:
- symmetric Gram matrix `Q`
- monomial degree `d`
- barrier budget `b`
- task source hash and proof hash

Runtime evaluates
- `score(x) = z(x)^T Q z(x)`
- `barrier(x) = b - score(x)`

A negative barrier value denotes a violated certified envelope.

## Soundness Claim
If `Q` is positive semidefinite (PSD), then `z^T Q z >= 0` for all basis vectors `z`.
Therefore `score(x)` is non-negative by construction. Runtime decision logic only relies on deterministic integer arithmetic over this quadratic form and fixed budget subtraction.

Build-time gate now enforces PSD feasibility via Cholesky decomposition with tolerance `1e-9`.
If decomposition fails, build fails.

## Implemented Verification
Build-time (`build.rs`) now performs:
1. Task parsing and structural validation (dimension, symmetry, shape)
2. PSD/Cholesky verification (`verify_psd_cholesky`)
3. Reconstruction residual analysis (`A - L L^T`)
4. Symbolic polynomial identity verification:
   - canonicalize quadratic terms for `z^TQz`
   - define `B(z) = b - z^TQz`, `sigma(z) = z^TQz`, `I(z) = B(z) - sigma(z)`
   - verify coefficient-wise that `B(z) = I(z) + sigma(z)` for each certificate family
5. Generated artifact constants for:
   - minimum pivot
   - max absolute reconstruction error
   - Frobenius residual norm (`stability_bound_delta`)
6. Generated JSON report: `OUT_DIR/sos_soundness_verification.json`
   - includes `cholesky_success` and `polynomial_identity_verified` fields per certificate

Runtime/test-time checks include:
- proof-hash integrity checks for all certificates
- PSD checks via principal minors
- generated soundness report coverage checks
- upper bounds on reconstruction/stability residuals
- explicit conjunction test for composed guards (fragmentation + memory-pressure-driven provenance)

## Barrier Invariance Companion
`bd-34s.2` also needs the runtime admissibility story, not only the offline SOS artifact story.
That companion surface lives in `crates/frankenlibc-membrane/src/runtime_math/barrier.rs`, where the checked-in proof tests establish:
- admissibility is monotone in risk,
- each guard is necessary,
- mode/profile/family coverage is total for the declared runtime surface.

The runtime-linkage side of the theorem is checked separately by:
- `scripts/check_runtime_math_linkage_proofs.sh`
- `tests/runtime_math/runtime_math_linkage.v1.json`

Together, these give the bead a concrete split:
- SOS soundness proves the offline certificate shape and integrity.
- Barrier invariance proves the runtime admission guard remains conservative and total on the shipped domain.

## Numerical Stability
The runtime evaluation path is integer/fixed-point based.
Floating-point is used in build-time Cholesky diagnostics only.

Recorded `stability_bound_delta` is the Frobenius norm of reconstruction residual:
- `delta = ||A - L L^T||_F`

Current test gate requires this bound to stay small (`<= 1e-5`) for all shipped certificates.

## Composition Argument
For certificates `B1(x)` and `B2(x)` guarding disjoint or coupled invariants, conjunction is represented operationally as enforcing both barrier predicates:
- safe iff `B1(x) >= 0` and `B2(x) >= 0`

This preserves soundness of each sufficient condition under conjunction; violation of either condition triggers escalation. The test suite includes an explicit conjunction check over fragmentation and memory-pressure-sensitive provenance barriers.

## Completeness Gap (Documented)
SOS certificates are sufficient but not complete for all nonnegative polynomials.
Known gap: existence of nonnegative polynomials that are not SOS-representable under fixed degree/basis constraints.

Implication:
- failure to find a certificate does not imply invariant is false
- synthesis degree/basis choices determine certifiable subset

## Follow-on Work
Remaining hardening items:
- formalized completeness-bound examples tied to concrete FrankenLibC invariants
- startup telemetry hook exposing `soundness_verified` summary in runtime logs
- richer forward-invariance arguments once the barrier state is widened beyond the current shipped domain
