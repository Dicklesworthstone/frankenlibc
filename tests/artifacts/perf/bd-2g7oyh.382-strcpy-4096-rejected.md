# bd-2g7oyh.382 - strcpy_4096 scan-then-bulk-copy rejection

## Target

- Bead: `bd-2g7oyh.382`
- Profile row: `glibc_baseline_strcpy_4096`
- Source surface: `crates/frankenlibc-core/src/string/str.rs`
- Broad routing basis: 2026-06-13 RCH sweep on `vmi1153651` at current
  `main` showed `strcpy_4096` as the largest unowned string residual:
  FrankenLibC p50 `133.431 ns`, mean `144.643 ns`; host glibc p50
  `77.661 ns`, mean `81.255 ns`.

Prior no-retry families:

- `bd-2g7oyh.356`: kept SWAR scan + wide copy common path.
- `bd-2g7oyh.355`: kept raw wide copy primitive.
- `bd-2g7oyh.322`: rejected certified-block `copy_from_slice` lowering.
- `bd-2g7oyh.246`: rejected final-block rank-select.

Alien-graveyard grounding: vectorized hot operators and register/cache-local
micro-kernel guidance point at reducing store-shape overhead in the certified
hot path, not changing C string semantics.

## Focused baseline

Command:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-382-strcpy4096-baseline-target-20260613T1412 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-382-strcpy4096-baseline-criterion-20260613T1412 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Selected worker: `vmi1153651`.

| impl | criterion interval | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC baseline | `[96.576 ns 101.10 ns 106.74 ns]` | `99.790` | `114.718` | `141.078` | `331.000` |
| host glibc | `[83.921 ns 86.803 ns 90.064 ns]` | `82.783` | `98.915` | `142.479` | `351.000` |

Focused residual reproduced by p50 (`1.21x`) and mean (`1.16x`).

## Candidate

One source lever in the exact `4096 + NUL` specialization only:

- Replace interleaved 512-byte "scan and SIMD-store" panels with scan-only
  `block_has_nul_512` certificates.
- If no early NUL exists, perform one bulk `4096`-byte `copy_from_slice` and
  write the known final terminator.
- If an early NUL exists, copy exactly `dest[..first_nul + 1]` and return.

This did not retry per-block `copy_from_slice` or final-block rank-select; it
was a whole-string store-shape probe after a full first-NUL certificate.

## Behavior proof

Final candidate proof command:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_BUILD_JOBS RUST_TEST_THREADS' \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
  cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1
```

Result on `vmi1153651`: passed `7/7`, including:

- `test_strcpy_exact_4096_path_preserves_tail_after_early_nul`
- `test_strcpy_golden_transcript_sha256`

Golden output SHA-256 asserted by the test stayed:

```text
fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401
```

Isomorphism:

- First-NUL ordering unchanged: the same 512-byte folded SIMD NUL certificate
  identifies candidate blocks, and exact resolution remains scalar
  left-to-right inside the first block containing NUL.
- For early-NUL exact-size sources, destination bytes through the terminator
  match `src[..first_nul + 1]`; bytes after the terminator remain untouched.
- For the no-early-NUL hot path, every byte before the known final NUL is
  copied and the final byte is written as NUL.
- Return count remains `first_nul + 1` or `4097`.
- Panic/no-NUL fallback, ordering/tie-breaking, floating-point, errno, and RNG
  are not involved.

## Post benchmark

Command:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-382-strcpy4096-post-target-20260613T1436 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-382-strcpy4096-post-criterion-20260613T1436 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Selected worker: `vmi1153651`.

| impl | criterion interval | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC candidate | `[96.955 ns 99.378 ns 101.77 ns]` | `98.115` | `100.458` | `112.655` | `120.000` |
| host glibc | `[75.068 ns 77.045 ns 79.090 ns]` | `78.126` | `87.283` | `120.000` | `262.645` |

Same-worker FrankenLibC delta:

- p50: `99.790 -> 98.115 ns` (`1.7%` faster)
- mean: `114.718 -> 100.458 ns` (`12.4%` faster)
- p95: `141.078 -> 112.655 ns`
- p99: `331.000 -> 120.000 ns`

Vs-host p50 gap widened from `1.21x` to `1.26x`, and the p50 self-win is too
small for a credible Score >= 2.0 keep despite better tails.

## Restore

The source lever was restored.

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: passed
- `git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs`: passed
- Restored `str.rs` SHA-256:
  `d07d697de272708875e8ae28a90629faa575bf0902e91039976613564f4f4586`

## Decision

REJECTED-RESTORED, Score `0.0`.

Do not retry whole-string scan-then-bulk-copy for this exact `strcpy_4096`
shape. The next attack should change the generated store strategy or route to a
different reproduced residual, not continue copy-shape micro-levers.
