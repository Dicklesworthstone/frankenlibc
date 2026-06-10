# bd-2g7oyh.322 - strcpy_4096 post-fused copy-shape rejection

## Target

- Bead: `bd-2g7oyh.322`
- Profile row: `glibc_baseline_strcpy_4096`
- Source surface: `crates/frankenlibc-core/src/string/str.rs`
- Broad profile basis: pass-48 RCH sweep at `6f49a7f3` on `vmi1227854`
  showed `strcpy_4096` as the strongest unowned residual after excluding
  peer-owned `pow*` and `strncmp`.

Broad row:

| impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | `52.027` | `53.226` | `62.500` | `75.500` |
| host glibc | `32.393` | `37.694` | `42.500` | `90.000` |

Prior `strcpy` routes:

- `bd-2g7oyh.273`: kept fused copy/NUL detection.
- `bd-2g7oyh.246`: rejected final-block rank-select.
- `bd-2g7oyh.256`: kept NUL-prefix certificate + bulk copy earlier.

## Focused baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
  RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-322-strcpy4096-baseline-target-20260610T0808 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-322-strcpy4096-baseline-criterion-20260610T0808 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Selected worker: `vmi1227854`.

| impl | criterion interval | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[38.087 ns 39.149 ns 40.112 ns]` | `39.504` | `41.135` | `43.875` | `60.500` |
| host glibc | `[31.671 ns 32.308 ns 32.945 ns]` | `33.502` | `35.341` | `41.209` | `65.000` |

Focused gap reproduced: FrankenLibC was `1.18x` slower by p50 and `1.16x`
slower by mean.

## Candidate

One source lever in `copy_nul_free_block_512`:

- Preserve the existing eight-panel safe-SIMD NUL certificate.
- If the block is NUL-free, copy the certified 512-byte block with
  `dest.copy_from_slice(src)` instead of eight `Simd::copy_to_slice` stores.

This deliberately did not retry final-block rank-select. It was a copy-shape
probe for certified blocks only; terminal-block resolution, fallback, and
panic paths were unchanged.

## Behavior proof

Local checks:

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`:
  passed.
- `git diff --check -- crates/frankenlibc-core/src/string/str.rs`: passed.

An initial broad RCH proof command:

```bash
cargo test -j 1 -p frankenlibc-core strcpy -- --nocapture --test-threads=1
```

was not counted because Cargo compiled unrelated integration tests first and
hit existing drift in `crates/frankenlibc-core/tests/strftime_differential_probe.rs`
(`BrokenDownTime` initializers missing `tm_gmtoff` and `zone`).

Counted proof command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
  RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CARGO_BUILD_JOBS RUST_TEST_THREADS' \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-322-strcpy-libproof-target-20260610T0815 \
  cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1
```

Result on `vmi1227854`: passed 6/6:

- `test_strcpy_basic`
- `test_strcpy_fused_path_copies_long_terminated_slice`
- `test_strcpy_fused_path_preserves_tail_after_early_nul`
- `test_strcpy_golden_transcript_sha256`
- `test_strcpy_no_nul_still_panics_without_synthetic_nul_room`
- `test_strcpy_stops_at_first_nul_without_touching_trailing_dest`

Isomorphism:

- First-NUL ordering unchanged: the same eight-panel folded certificate is
  used and terminal blocks still resolve left-to-right.
- Destination writes unchanged for certified NUL-free blocks: every byte in
  the block is before the first NUL and must be copied by `strcpy`.
- Terminal block behavior unchanged: no bytes past the first NUL are written.
- Panic/no-NUL fallback unchanged.
- Floating-point, RNG, and errno are not involved.

## Post benchmark

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
  RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-322-strcpy4096-post-target-20260610T0818 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-322-strcpy4096-post-criterion-20260610T0818 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Selected worker: `vmi1227854`.

| impl | criterion interval | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC candidate | `[61.187 ns 63.063 ns 64.943 ns]` | `62.000` | `69.901` | `72.534` | `100.000` |
| host glibc | `[32.780 ns 33.425 ns 34.098 ns]` | `34.559` | `37.990` | `64.816` | `103.246` |

Same-worker candidate delta:

- FrankenLibC p50 regressed `39.504 -> 62.000 ns`.
- FrankenLibC mean regressed `41.135 -> 69.901 ns`.

## Restore

The source was restored after the post benchmark.

- `git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs`: passed
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`:
  passed
- Restored `str.rs` sha256:
  `5eb2974530ce7264233c9788e0ded187cd318aeb794ebaf88a4d94ef7fbbe8ef`

## Decision

REJECTED-RESTORED, Score `0.0`.

Do not retry certified-block `copy_from_slice` lowering. Do not retry
final-block rank-select or the existing fused scan/store family. The next
`strcpy_4096` attack needs a deeper primitive, such as a generated-code backed
bounded store strategy that keeps the terminal-block no-overwrite contract, or
route to a different reproduced residual like allocator lifecycle work.
