# FrankenLibC Release Readiness Scorecard

Last updated: 2026-06-19 by `cod-b` / `BlackThrush`.

## Current gate snapshot

| Area | Score | Evidence | Risk |
|---|---:|---|---|
| Measured perf backlog conversion | 2 / many pending | `bd-0m5vaw` and `bd-fgnxc0` converted from code-first pending to measured head-to-head wins vs host glibc. | Large backlog remains across stdio registry, resolver/NSS parser, string, allocator, and peer-owned leaves. |
| Negative-evidence ledger | 1 / committed ledger | `docs/NEGATIVE_EVIDENCE.md` now records win/loss/neutral policy and the first two measured rows with glibc ratios. | Existing per-bead artifacts still contain many pending local ledgers; central ledger needs every later result appended. |
| Revert discipline | Green for measured cluster | No revert needed: both measured rows beat host glibc with ratios 0.856x and 0.313x. | Future neutral/loss rows must be reverted or explicitly marked safety/correctness exceptions. |
| Conformance guard | Partial green | `cargo check -p frankenlibc-abi` passed with known warning debt. Criterion bench binaries built and ran successfully. | `cargo test -p frankenlibc-abi` is blocked by pre-existing `zz_scratch_divmin` scratch-test compile errors; `stdio_abi`/`wchar_abi` inline tests are gated out of `--lib` test mode. |
| Release posture | Not ready | Two real wins recorded, no new source regression in this pass. | Not release-ready until scratch test debt is isolated/fixed, central ledger covers the pending backlog, and conformance/bench gates are repeatable. |

## 2026-06-19 measured stdio cluster

| Bead | Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---|---:|---:|---:|---|---|
| `bd-0m5vaw` | `snprintf("%s\n")` with 128-byte destination and stable log payload | 471.49 ns | 550.41 ns | 0.856x | WIN | Keep. |
| `bd-fgnxc0` | `swprintf(L"value=%d\n")` into 32-wide-char buffer | 317.94 ns | 1.0154 us | 0.313x | WIN | Keep. |

## Blocking follow-ups

- Move or gate `zz_scratch_*` integration probes so crate-scoped test filters can build the intended test binary without unrelated scratch compile failures.
- Add test-mode-safe coverage for `stdio_abi` and `wchar_abi` helper tests, or move the helper invariants into a module that is built under `cargo test --lib`.
- Continue converting `code-first batch-test pending` beads into central ledger rows, starting with `bd-2jgvp9` stdio registry local hasher and cod-b-owned resolver/NSS parser rows.
