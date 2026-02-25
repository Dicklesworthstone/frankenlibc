# Hardened Mode Safety Proof (bd-249m.2)

## Scope
- Theorem: hardened mode applies deterministic repair/deny behavior for declared invalid-input classes on membrane-gated paths.
- Runtime scope in this artifact: invalid-input classes enumerated in `tests/conformance/hardened_repair_deny_matrix.v1.json`.
- Coverage scope today: StringMemory, WideChar, Iconv, Poll, Locale, VirtualMemory, Startup, Socket, Signal, Resource, and Termios families.

## Statement
For each covered symbol `s`, invalid-input class `c`, and input `x` classified as `c`:

`FrankenHardened(s, x) = Decision(c, s)`, where `Decision(c, s)` is fixed to exactly one of:
- `Repair(healing_action)` with deterministic transformed output, or
- `Deny` with deterministic POSIX error result.

For covered valid inputs, hardened mode remains behavior-compatible with the strict/reference expectation set for the same fixture corpus.

## Determinism Obligations
- Decision identity is stable and auditable via deterministic `policy_id` strings (`tsm.(repair|deny).<family>.<class>.v1`) in `tests/conformance/hardened_repair_deny_matrix.v1.json`.
- Gate enforcement: `scripts/check_hardened_repair_deny_matrix.sh` rejects non-deterministic/duplicate policy IDs, missing class coverage, and drift between matrix `known_healing_actions` and live `HealingAction` variants in `crates/frankenlibc-membrane/src/heal.rs`.
- Integration enforcement: `crates/frankenlibc-harness/tests/hardened_repair_deny_matrix_test.rs` runs the gate in CI/test flow.

## Totality and Safety Mapping
- Every declared invalid-input class in the matrix has at least one entry (totality over the declared set).
- Every matrix entry resolves to a hardened fixture case and a deterministic expected outcome.
- Gate output includes a deterministic canonical policy mapping hash (`summary.policy_mapping_sha256`) so matrix drift is immediately detectable.
- Repair/deny to POSIX-facing outcomes is enumerated in `docs/proofs/repair_posix_mapping.md`.

## Traceability Anchors
- `crates/frankenlibc-membrane/src/heal.rs`
  deterministic healing action vocabulary and global policy counters.
- `crates/frankenlibc-membrane/src/runtime_math/mod.rs`
  runtime decision + policy ID composition used for action explainability.
- `crates/frankenlibc-abi/src/runtime_policy.rs`
  ABI boundary decision projection and explainability/event recording.
- `tests/conformance/hardened_repair_deny_matrix.v1.json`
  machine-readable proof surface for class -> action -> fixture evidence.
- `scripts/check_hardened_repair_deny_matrix.sh`
  machine gate for matrix validity and deterministic policy identity.

## Evidence Path
- Deterministic matrix: `tests/conformance/hardened_repair_deny_matrix.v1.json`
- Gate script: `scripts/check_hardened_repair_deny_matrix.sh`
- Harness integration test: `crates/frankenlibc-harness/tests/hardened_repair_deny_matrix_test.rs`
- Deterministic coverage report: `target/conformance/hardened_repair_deny_matrix.report.json`
- Structured gate log: `target/conformance/hardened_repair_deny_matrix.log.jsonl`
- Fixture corpus: `tests/conformance/fixtures/*.json` (referenced per entry in matrix)
- POSIX mapping companion: `docs/proofs/repair_posix_mapping.md`

## Status
This artifact establishes hardened-mode deterministic repair/deny evidence for the currently declared invalid-input classes.
Full project-level closure still requires extending the matrix as additional membrane-gated symbol families gain hardened invalid-input fixtures.
