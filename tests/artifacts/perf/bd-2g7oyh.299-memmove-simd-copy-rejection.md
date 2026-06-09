# bd-2g7oyh.304 - memmove_4096 safe-SIMD copy rejection

Date: 2026-06-09
Agent: BoldFalcon
Target: `glibc_baseline_memmove_4096` / `crates/frankenlibc-core/src/string/mem.rs`

Canonical bead after rebase: `bd-2g7oyh.304`. The artifact filename retains the scratch-issued `bd-2g7oyh.299` prefix because it was created before upstream consumed `.299`.

## Profile-Backed Target

Post-pass-31 broad RCH profile on `ovh-a` showed the largest unowned copy/move residual:

- FrankenLibC `memmove_4096`: p50 `47.508 ns`, mean `48.592 ns`
- host glibc `memmove_4096`: p50 `31.097 ns`, mean `33.578 ns`
- apparent gap: `1.53x` p50 / `1.45x` mean

Focused same-worker baseline on `ovh-a` reproduced a smaller but real gap:

- FrankenLibC: p50 `37.655 ns`, mean `39.084 ns`, p95 `45.423 ns`, p99 `50.387 ns`
- host glibc: p50 `31.538 ns`, mean `33.093 ns`, p95 `37.500 ns`, p99 `45.500 ns`
- focused gap: `1.19x` p50 / `1.18x` mean

`ovh-a` then became unavailable for post scoring because RCH marked it under disk-pressure telemetry. To avoid cross-worker scoring, an untouched `HEAD` worktree was created at:

`/data/projects/.scratch/frankenlibc-pass32-baseline-head-20260609`

and both baseline and post were measured on `vmi1227854`.

## Lever Tested

One source lever was tested and then rejected:

- Add a safe portable-SIMD large-copy path to core `memmove(&mut [u8], &[u8], n)`.
- For counts >= `1024`, copy 64 bytes per panel with `Simd::<u8, 64>::from_slice(...).copy_to_slice(...)`.
- Preserve the existing `copy_from_slice` tail and small-copy path.

This was an algorithmically different safe-Rust copy primitive, not a host libc delegation and not unsafe code.

## Isomorphism Proof

- API preserved: yes. `memmove` still returned `min(n, dest.len(), src.len())`.
- Byte ordering preserved: yes. The SIMD path copied panels in increasing offset order and copied the same prefix bytes as `copy_from_slice`.
- Tie-breaking: N/A.
- Floating point: N/A.
- RNG: N/A.
- Golden SHA-256 unchanged:
  - `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
  - `tests/conformance/fixtures/memcpy_strict.json`: `6bdd6fb00bff508d07eb985bdc7c258a1a10f8ea96de72cf7e392483e886c233`
  - `tests/conformance/perf_baseline_spec.json`: `6a7fced48f32a9c9ee38a5a8654f408c1a56a034bac6e5fc484d98c39b2af6b3`
  - `tests/conformance/perf_budget_policy.json`: `d2466951e02b69d009784994c9c79da7d5c4d9edafc38b9f184686990d297110`

Proof run:

```text
RCH worker: ovh-a
Command: cargo test -j 2 -p frankenlibc-core --lib prop_memmove_matches_prefix_copy -- --nocapture --test-threads=1
Result: passed, 1 test; 3082 filtered out
```

The broader `cargo test -p frankenlibc-core prop_memmove_matches_prefix_copy` command was blocked by unrelated pre-existing test-target breakage in `crates/frankenlibc-core/tests/strftime_buffer_differential_probe.rs` (`BrokenDownTime` missing `tm_gmtoff`).

Formatting:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
Result: passed
```

`cargo fmt -p frankenlibc-core --check` remains blocked by broad pre-existing unrelated formatting drift in other files and generated tables.

## Same-Worker Scoring Rows

Comparable baseline on `vmi1227854`, untouched `HEAD`:

- FrankenLibC: p50 `31.962 ns`, mean `34.252 ns`, p95 `38.469 ns`, p99 `70.500 ns`
- host glibc: p50 `28.285 ns`, mean `30.398 ns`, p95 `34.964 ns`, p99 `65.000 ns`

Candidate post on `vmi1227854`:

- FrankenLibC: p50 `42.415 ns`, mean `43.229 ns`, p95 `52.378 ns`, p99 `70.000 ns`
- host glibc: p50 `28.913 ns`, mean `31.079 ns`, p95 `33.331 ns`, p99 `70.000 ns`

## Verdict

REJECTED and source restored.

- FrankenLibC p50 regressed `31.962 ns -> 42.415 ns` (`32.7%` slower).
- FrankenLibC mean regressed `34.252 ns -> 43.229 ns` (`26.2%` slower).
- Score: `0.0`.
- `git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs` passed after restoration.

## Next Route

Do not retry the portable-SIMD copy panel family for core `memmove`. The compiler/libcore intrinsic path is already better for this workload on `vmi1227854`.

Next deeper primitive: use disassembly-backed copy-codegen work before touching source again, or reroute to a different profiled residual. A plausible next systems primitive is an RCH-compatible assembly extraction sidecar for safe string/memory kernels, then test whether array-reference equality/copy lowering, ISA feature selection, or ABI raw-pointer dispatch is the actual residual.
