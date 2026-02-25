# Strict Mode Refinement Proof (bd-249m.1)

## Scope and Snapshot
- Theorem target: strict mode is a refinement of the current FrankenLibC/glibc contract on declared domains.
- Snapshot source: `tests/conformance/reality_report.v1.json` (`generated_at_utc=2026-02-25T05:35:12Z`).
- Exported scope in this snapshot: 993 symbols (`implemented=595`, `raw_syscall=297`, `glibc_call_through=101`, `stub=0`).
- Input domain: POSIX-defined inputs plus explicit strict-mode fixture contracts.

## Formal Statement
For each supported symbol `s` and valid input `x` in the strict conformance domain:

`FrankenStrict(s, x) = Glibc(s, x)` and `errno_strict(s, x) = errno_glibc(s, x)`.

For membrane transparency in strict mode:

`TSM_strict(f(x)) = f(x)`.

## Simulation Relation
Let:
- `C` be concrete FrankenLibC runtime state (ABI + membrane + core).
- `A` be abstract glibc-visible state `(return, errno, observable side-effects)`.
- `alpha: C -> A` be projection to observables.

Refinement obligation:
- If glibc transitions `A --(s,x)--> A'`, and `alpha(C) = A`, then strict-mode FrankenLibC transitions `C --(s,x)--> C'` such that `alpha(C') = A'`.

## Machine-Checked Traceability Anchors
- `crates/frankenlibc-membrane/src/config.rs:99`
  strict default and process-sticky mode resolution.
- `crates/frankenlibc-membrane/src/ptr_validator.rs:1197`
  strict fast-profile path skips deep integrity/healing behavior.
- `crates/frankenlibc-membrane/src/decision_contract.rs:214`
  strict/off modes project active contract actions to `Log`.
- `crates/frankenlibc-abi/src/runtime_policy.rs:673`
  decision contract application for runtime policy explainability.
- `crates/frankenlibc-abi/src/runtime_policy.rs:1399`
  strict-mode unit test asserting contract action projection to `Log`.
- `crates/frankenlibc-abi/src/errno_abi.rs:10`
  ABI `__errno_location` thread-local pointer source.
- `crates/frankenlibc-core/src/errno/mod.rs:7`
  core thread-local errno cell definition.
- `crates/frankenlibc-core/src/errno/mod.rs:133`
  core `get_errno` accessor semantics.
- `crates/frankenlibc-abi/src/math_abi.rs:69`
  strict/hardened decision routing at math unary entrypoint.
- `crates/frankenlibc-abi/src/fenv_abi.rs:74`
  strict rounding-mode read path delegated through ABI fenv surface.

## Evidence and Reproduction
- Fixture parity artifact:
  `tests/conformance/golden/fixture_verify_strict_hardened.v1.json`
- Binder and source-ref gate:
  `bash scripts/check_proof_binder.sh`
- Traceability report refresh:
  `python3 scripts/gentoo/proof_binder_validator.py --dry-run --format json --no-hashes --output tests/conformance/proof_traceability_check.json`

## Current Status
- Status: in progress.
- Completed in this phase: refreshed strict-refinement theorem statement, updated source anchors to current code, and synchronized machine-checkable binder/report artifacts.
- Remaining for closure: exhaustive symbol-domain argumentation, full strict transparency stress evidence across declared fixture families, and independent review sign-off.
