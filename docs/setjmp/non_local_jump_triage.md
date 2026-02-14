# Setjmp Non-Local Jump Triage (bd-ahjd)

## Scope
This triage guide covers deterministic diagnosis for `tests/conformance/fixtures/setjmp_nested_edges.json`.

## Supported Fixture Programs
- `tests/integration/fixture_setjmp_nested.c`
  - Scenario: `nested_two_level_longjmp`
  - Expected strict/hardened output: `fixture_setjmp_nested: PASS`
- `tests/integration/fixture_setjmp_edges.c`
  - Scenario: `edge_zero_value_and_sigmask_roundtrip`
  - Expected strict/hardened output: `fixture_setjmp_edges: PASS`

## Unsupported Scenarios (Explicitly Deferred)
- `cross_thread_longjmp`
  - Expected outcome: `unsupported_deferred`
  - Expected errno class: `ENOSYS`
- `corrupted_jump_buffer_restore`
  - Expected outcome: `unsupported_deferred`
  - Expected errno class: `EFAULT`
- `siglongjmp_without_sigsetjmp`
  - Expected outcome: `unsupported_deferred`
  - Expected errno class: `EINVAL`

## Failure Signatures
- Compile failure
  - Signature: `cc failed for scenario <id>`
  - First check: toolchain/headers for `setjmp.h`
- Runtime exit mismatch
  - Signature: `unexpected exit code`
  - First check: scenario expected profile in fixture JSON
- Output mismatch
  - Signature: `stdout does not contain expected token`
  - First check: fixture binary emitted PASS line exactly
- Deferred semantics drift
  - Signature: `unsupported scenario missing explicit semantics`
  - First check: `unsupported_scenarios[*].expected_outcome` and `expected_errno`

## Replay
- Run: `scripts/check_setjmp_fixture_pack.sh`
- Artifacts:
  - `target/conformance/setjmp_fixture_pack.report.json`
  - `target/conformance/setjmp_fixture_pack.log.jsonl`
  - `tests/cve_arena/results/bd-ahjd/trace.jsonl`
  - `tests/cve_arena/results/bd-ahjd/artifact_index.json`
