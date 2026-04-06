# Deterministic Replay Proof (bd-34s.1)

## Scope
- Theorem target: replaying the same `(mode, input trace, environment fingerprint)` yields identical runtime decisions and evidence outputs.
- Covered surfaces in this phase:
  - runtime mode resolution and startup stickiness,
  - runtime-math decision stream replay,
  - deterministic E2E replay key generation and structured-log verification.

## Formal Statement
Let
- `m` be the resolved runtime mode (`strict` or `hardened`),
- `T = [c1, c2, ..., cn]` be an ordered call trace where each `ci` is `(api_family, context, estimated_cost, adverse_flag)`,
- `E` be the replay environment fingerprint (seed + manifest hash + timeout + mode + library path).

Deterministic replay obligation:

`Replay(m, T, E)_run1 == Replay(m, T, E)_run2`

for:
1. decision stream sequence,
2. evidence counters and contract snapshot,
3. emitted structured runtime decision logs (modulo timestamp fields).

## Determinism Contract Boundaries
- Explicitly deterministic:
  - mode resolution cache/stickiness after first parse,
  - runtime math `decide + observe_validation_result` replay on identical scripted contexts,
  - E2E replay-key derivation and environment fingerprinting.
- Explicitly non-deterministic classes (out of theorem scope):
  - wall-clock/time APIs,
  - entropy-backed randomness APIs,
  - external environment mutation between runs.

## Machine-Checked Traceability Anchors
- `crates/frankenlibc-membrane/src/config.rs:99`
  mode parse/cache entrypoint used by membrane runtime.
- `crates/frankenlibc-abi/src/runtime_policy.rs:266`
  ABI runtime mode resolution wrapper.
- `crates/frankenlibc-abi/src/runtime_policy.rs:1234`
  sticky mode test (`mode_resolution_is_sticky_until_cache_reset`).
- `crates/frankenlibc-membrane/src/runtime_math/mod.rs:6286`
  deterministic replay unit test for identical decision/evidence traces.
- `crates/frankenlibc-membrane/tests/runtime_math_dual_mode_e2e_test.rs:72`
  end-to-end replay test asserting identical decision logs after timestamp normalization.
- `scripts/e2e_suite.sh:400`
  deterministic replay-key construction from fixed replay inputs.
- `scripts/e2e_suite.sh:612`
  replay execution pins mode + seed for deterministic scenario runs.
- `scripts/check_e2e_suite.sh:102`
  deterministic gate seed export for CI replay consistency.
- `scripts/check_e2e_suite.sh:154`
  structured-log gate requiring replay metadata fields.

## Evidence and Reproduction
- Proof binder gate:
  - `bash scripts/check_proof_binder.sh`
- Traceability report refresh:
  - `python3 scripts/gentoo/proof_binder_validator.py --dry-run --format json --no-hashes --output tests/conformance/proof_traceability_check.json`
- Deterministic E2E suite gate:
  - `bash scripts/check_e2e_suite.sh`

## Current Status
- Status: binder-wired for `bd-34s.1`.
- Completed in this phase:
  - added deterministic replay theorem artifact,
  - wired `PO-03` to `bd-34s.1` ownership and current source anchors in the binder,
  - synchronized proof traceability report with PO-03 source-reference checks.
- Remaining before closure:
  - symbol-level purity classification artifact (`pure/impure` map with explicit implicit-state dependencies),
  - concurrent replay schedule harness and evidence,
  - reviewer sign-off on the full theorem argument as more replay-sensitive surfaces are promoted.
