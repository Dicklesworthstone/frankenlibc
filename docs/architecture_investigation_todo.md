# FrankenLibC Architecture Investigation + Migration TODO Ledger

Last updated: 2026-02-13

> Archived historical investigation ledger. The checkbox state below is preserved
> as the 2026-02-13 investigation snapshot; do not treat unchecked rows below as live backlog.
> Live tracker truth is `br ready --no-db --json`,
> `br list --status open --no-db --json`, and
> `tests/conformance/architecture_ledger_live_evidence_completion_contract.v1.json`.

This ledger tracks investigation follow-ups and migration work discovered during deep codebase architecture analysis.

Status keys:
- `[x]` completed
- `[~]` in progress
- `[ ]` pending
- `[!]` blocked

## 0) Completed In This Pass

- [x] `TODO-0001` Read `AGENTS.md` end-to-end.
- [x] `TODO-0002` Read `README.md` end-to-end.
- [x] `TODO-0003` Build full workspace architecture map (membrane/core/abi/harness/bench/fuzz + scripts/tests).
- [x] `TODO-0004` Build symbol-family inventory from `support_matrix.json`.
- [x] `TODO-0005` Build strict vs hardened fixture coverage inventory (`tests/conformance/fixtures/*.json`).
- [x] `TODO-0006` Run replacement/interpose guard scripts and collect findings.
- [x] `TODO-0007` Run support-matrix drift check and collect findings.
- [x] `TODO-0008` Introduce adapter seam crate: `crates/frankenlibc-fixture-exec`.
- [x] `TODO-0009` Remove direct `frankenlibc-harness -> frankenlibc_conformance` dependency.
- [x] `TODO-0010` Rewire harness imports to adapter seam.
- [x] `TODO-0011` Validate with `cargo check -p frankenlibc-harness`.
- [x] `TODO-0012` Validate with `cargo test -p frankenlibc-harness --lib runner::`.
- [x] `TODO-0013` Validate conformance golden stability via `scripts/conformance_golden_gate.sh`.

## 1) P0 Correctness + Drift

- [x] `TODO-0101` Resolve support-matrix drift source of truth mismatch.
- [ ] `TODO-0102` Define one canonical generator path for `support_matrix.json`.
- [x] `TODO-0103` Define one canonical generator path for `tests/conformance/reality_report.v1.json`.
- [ ] `TODO-0104` Add CI assertion that matrix and reality report are regenerated together in one step.
- [ ] `TODO-0105` Add deterministic regeneration script wrapper (single command for both artifacts).
- [x] `TODO-0106` Update docs to state authoritative artifact ownership and regeneration flow.
- [ ] `TODO-0107` Add a drift triage report artifact with per-symbol deltas.

## 2) P0 Replacement Readiness

- [x] `TODO-0201` Triage replacement guard report and enumerate all `GlibcCallThrough` blockers by module.
- [~] `TODO-0202` Prioritize blockers by workload impact (`tests/conformance/workload_matrix.json` mapping).
- [~] `TODO-0203` Eliminate highest-impact call-throughs first: allocator/threading/string families.
  - [x] `TODO-0203a` Remove `termios_abi` host-libc call-throughs:
    - `tcgetattr/tcsetattr/tcdrain/tcflush/tcflow/tcsendbreak` now routed through `sys_ioctl`.
    - `cfgetispeed/cfgetospeed/cfsetispeed/cfsetospeed` now use direct `termios` flag math + validation.
  - [x] `TODO-0203b` Remove `dirent_abi` host-libc call-throughs:
    - `opendir` now uses `sys_openat`.
    - `closedir` now uses `sys_close`.
    - `readdir` `getdents64` path now uses `sys_getdents64`.
  - [x] `TODO-0203c` Remove `signal_abi` host-libc call-throughs for signal delivery:
    - `raise` now routes via `SYS_kill` to `sys_getpid()`.
    - `kill` now routes via `SYS_kill`.
  - [x] `TODO-0203d` Remove `socket_abi` host-libc call-throughs:
    - `socket/bind/listen/accept/connect`
    - `send/recv/sendto/recvfrom`
    - `shutdown/setsockopt/getsockopt/getpeername/getsockname`
    - all now route through raw `SYS_*` syscall entrypoints with explicit errno mapping.
  - [x] `TODO-0203e` Remove `unistd_abi` host-libc call-throughs:
    - metadata/navigation/identity/link path now route through raw `SYS_*` syscall entrypoints.
    - `stat/lstat` use `newfstatat`, `access` uses `faccessat`, link ops use `*at` variants.
    - `sleep/usleep` now route through `SYS_nanosleep`.
  - [ ] `TODO-0203f` Remove remaining `signal_abi` call-throughs:
    - `signal`
    - `sigaction`
- [ ] `TODO-0204` Eliminate remaining call-throughs in loader/resolver/locale families.
- [ ] `TODO-0205` Re-run `scripts/check_replacement_guard.sh replacement` until zero forbidden call-throughs.
- [ ] `TODO-0206` Add regression test to prevent reintroduction of replacement-mode call-throughs.

## 3) P0 Fixture Schema Stability

- [x] `TODO-0301` Fix fixture schema heterogeneity causing skip in verify flow.
- [x] `TODO-0302` `elf_loader.json` missing `expected_errno` for cases expected by `FixtureCase`.
- [x] `TODO-0303` `resolver.json` has non-string `expected_output` while harness expects string.
- [x] `TODO-0304` Decide canonical schema for `expected_output` (string-only vs tagged value).
  - Closed by `bd-0agsk.5`: canonical boundary is tagged expected-value records normalized by harness adapters into the internal string comparison form. Evidence: `tests/conformance/fixture_expected_output_schema_policy.v1.json`, `scripts/check_fixture_expected_output_schema_policy.sh`, and `crates/frankenlibc-harness/tests/fixture_expected_output_schema_policy_test.rs`.
- [x] `TODO-0305` Implement schema adapter in loader if mixed typing remains necessary.
- [x] `TODO-0306` Add schema validation script for all fixture files.
  - Closed by `bd-0agsk.6` and completion-debt closeout `bd-0agsk.6.1`: whole-tree fixture schema gate validates every `tests/conformance/fixtures/*.json` file and emits structured report/log telemetry. Evidence: `tests/conformance/fixture_schema_validation.v1.json`, `scripts/check_fixture_schema_validation.sh`, `crates/frankenlibc-harness/tests/fixture_schema_validation_test.rs`, and `tests/conformance/fixture_schema_validation_telemetry_index.v1.json`.
- [x] `TODO-0307` Add integration test to ensure `harness verify` processes all fixture files (no silent skips).

## 4) P0 Harness/Conformance Migration (Phase B+)

- [x] `TODO-0401` Introduce execution adapter seam crate (`frankenlibc-fixture-exec`).
- [x] `TODO-0402` Define target-state ownership for fixture execution logic (legacy crate vs new shared crate).
  - Closed by `bd-0agsk.7`: `tests/conformance/fixture_executor_ownership_and_golden.v1.json` defines `frankenlibc-fixture-exec` as the stable public boundary, keeps `frankenlibc_conformance` as a compatibility package path, and forbids direct harness dependency on legacy internals.
- [x] `TODO-0403` Extract `execute_fixture_case` implementation from `frankenlibc_conformance` into owned shared crate/module.
  - Closed by `bd-0agsk.8`: `crates/frankenlibc-fixture-exec/src/lib.rs` owns the public executor boundary, while `crates/frankenlibc_conformance/Cargo.toml` now points its library target at the fixture-exec entrypoint for compatibility.
- [x] `TODO-0404` Keep output format bit-for-bit stable during extraction (golden hash invariant).
  - Closed by `bd-0agsk.7`/`bd-0agsk.8`: the fixture executor golden manifest and `crates/frankenlibc-harness/tests/fixture_executor_ownership_and_golden_test.rs` pin seven representative `execute_fixture_case` payload hashes.
- [x] `TODO-0405` Decommission redundant glue in `frankenlibc_conformance` once extraction completes.
  - Closed by `bd-0agsk.8`: the legacy crate is retained only as a compatibility package path because file deletion is forbidden; the Cargo library target reuses `../frankenlibc-fixture-exec/src/lib.rs`.
- [x] `TODO-0406` Add migration note documenting why harness forbids `unsafe` and where host-libc unsafe calls live.
  - Closed by `bd-0agsk.8`: `tests/conformance/fixture_executor_ownership_and_golden.v1.json` records that the ownership inversion introduces no new unsafe boundary and keeps host-oracle unsafe calls behind the fixture-exec public boundary.

## 5) P1 Fixture Depth + Mode Coverage

- [ ] `TODO-0501` Increase hardened-mode coverage beyond current low baseline.
- [ ] `TODO-0502` Add hardened-specific fixtures for allocator anomaly repairs.
- [ ] `TODO-0503` Add hardened-specific fixtures for parser/locale boundary conditions.
- [ ] `TODO-0504` Add hardened-specific fixtures for resolver retry/cache instability cases.
- [ ] `TODO-0505` Add strict/hardened pair fixtures for every high-risk symbol family in support matrix.
- [ ] `TODO-0506` Add fixture-coverage dashboard keyed by module family and mode.

## 6) P1 Symbol & ABI Coverage Expansion

- [ ] `TODO-0601` Expand implemented symbol coverage for top blocker modules in `support_matrix.json`.
- [ ] `TODO-0602` For each newly implemented symbol, add fixture entry and expected output.
- [ ] `TODO-0603` Keep `version_scripts/libc.map` parity checks in lockstep with symbol additions.
- [ ] `TODO-0604` Add per-family acceptance thresholds tied to replacement readiness.

## 7) P1 Runtime-Mode Governance

- [ ] `TODO-0701` Verify process-immutable mode selection (`FRANKENLIBC_MODE`) across all entrypoints.
- [ ] `TODO-0702` Add explicit startup-mode evidence line in structured logs for every harness campaign.
- [ ] `TODO-0703` Add test coverage for mode mismatch handling in subprocess-orchestrated flows.

## 8) P1 Runtime Math Kernel Contract Tracking

- [ ] `TODO-0801` Reconcile mandatory live runtime_math module list in docs with actual source tree inventory.
- [ ] `TODO-0802` Add machine-checked linkage report for all required kernels under `runtime_math/mod.rs`.
- [ ] `TODO-0803` Ensure production-monitor classification policy remains consistent with governance artifacts.
- [ ] `TODO-0804` Ensure retired/experimental kernel sets cannot leak into production-monitor set.
- [ ] `TODO-0805` Add CI gate: required modules present + linked + classified.

## 9) P1 Tooling Requirements (/dp/asupersync + /dp/frankentui)

- [ ] `TODO-0901` Verify deterministic orchestration path always uses `/dp/asupersync` when feature-enabled.
- [ ] `TODO-0902` Verify diff/snapshot UI path uses `/dp/frankentui` when feature-enabled.
- [ ] `TODO-0903` Add explicit “tooling only, not runtime dependency” audit assertions in CI.

## 10) P2 Architecture Documentation Hygiene

- [ ] `TODO-1001` Add architecture diagram from workspace crates to major artifact flows.
- [ ] `TODO-1002` Add migration-state section (interpose-ready vs replacement-ready by module family).
- [ ] `TODO-1003` Add glossary for strict/hardened semantics in fixture and report context.
- [ ] `TODO-1004` Add contributor quickstart for reproducing all gates locally in deterministic order.

## 11) Immediate Next Execution Queue

- [x] `NEXT-0001` Regenerate/normalize fixture schemas so verify path stops skipping `elf_loader.json` and `resolver.json`.
- [x] `NEXT-0002` Close support-matrix vs reality-report drift with a single canonical generation pass.
- [~] `NEXT-0003` Burn down highest-impact replacement call-through blockers and re-run replacement guard.
  - Progress note (pass 1): replacement guard reduced from 80 -> 70 forbidden call-throughs by removing host-libc calls in `time_abi`, `resource_abi`, `process_abi`, and `stdlib_abi`.
  - Progress note (pass 2): replacement guard reduced from 70 -> 56 forbidden call-throughs by removing host-libc calls in `termios_abi`, `dirent_abi`, and `signal_abi` (`raise`/`kill`).
  - Progress note (pass 3): replacement guard reduced from 56 -> 22 forbidden call-throughs by removing host-libc calls in `socket_abi` and `unistd_abi`.
  - Current blocker distribution (`replacement_guard.report.json`):
    - `pthread_abi`: 15
    - `dlfcn_abi`: 4
    - `signal_abi`: 2
    - `startup_abi`: 1
  - Previously resolved distributions:
    - resolved in this pass:
      - `socket_abi`: 14 -> 0
      - `unistd_abi`: 20 -> 0
    - resolved in earlier pass:
      - `termios_abi`: 10 -> 0
      - `dirent_abi`: 2 -> 0
    - resolved in earlier pass:
      - `signal_abi`: 4 -> 2
