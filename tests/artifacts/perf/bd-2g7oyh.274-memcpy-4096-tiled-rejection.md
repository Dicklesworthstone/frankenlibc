# bd-2g7oyh.274 memcpy_4096 portable-SIMD tiled copy

Status: REJECTED on 2026-06-08.

## Target

- Bead: `bd-2g7oyh.274`
- Scope: `crates/frankenlibc-core/src/string/mem.rs`
- Profile-backed target: `glibc_baseline_memcpy_4096`
- Candidate lever: exact 4096-byte safe portable-SIMD tiled copy path in `memcpy`

Fresh broad RCH profile on `vmi1152480` selected this row:

| Row | FrankenLibC p50 | FrankenLibC mean | FrankenLibC p95 | FrankenLibC p99 | host p50 | host mean | host p95 | host p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `memcpy_4096` | 42.759 ns | 46.694 ns | 52.500 ns | 140.000 ns | 29.828 ns | 35.228 ns | 40.250 ns | 161.000 ns |

Focused same-worker pre-edit baseline on `vmi1152480`:

| Row | FrankenLibC p50 | FrankenLibC mean | FrankenLibC p95 | FrankenLibC p99 | host p50 | host mean | host p95 | host p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `memcpy_4096` | 43.030 ns | 45.624 ns | 48.178 ns | 70.000 ns | 28.785 ns | 31.457 ns | 37.615 ns | 65.000 ns |

Command:

```bash
env RCH_WORKER=vmi1152480 RCH_PREFERRED_WORKER=vmi1152480 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary AGENT_NAME=BoldFalcon RCH_BUILD_SLOTS=2 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd274-baseline-vmi1152480 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memcpy_4096 --noplot --sample-size 35 --warm-up-time 1 --measurement-time 2
```

## Candidate

One lever only: add a `count == 4096` path in `memcpy` that copied eight
512-byte tiles. Each tile loaded and stored eight `Simd<u8, 64>` vectors.
Every other count fell through to the existing `copy_from_slice` path.

This differed from the previously rejected exact-size branch family that only
routed 4096 bytes to another slice copy. The intended primitive was an explicit
portable-SIMD tiled data path.

## Behavior Proof

RCH proof command:

```bash
env RCH_WORKER=vmi1152480 RCH_PREFERRED_WORKER=vmi1152480 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary AGENT_NAME=BoldFalcon RCH_BUILD_SLOTS=2 rch exec -- env AGENT_NAME=BoldFalcon RUST_TEST_THREADS=1 FRANKENLIBC_PROPTEST_CASES=512 CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd274-proof-vmi1152480 cargo test -p frankenlibc-core memcpy -- --nocapture --test-threads=1
```

Result: passed all targeted memcpy proof tests:

- `string::mem::tests::prop_memcpy_matches_prefix_copy`
- `string::mem::tests::test_memcpy_basic`
- `string::mem::tests::test_memcpy_exact_4096_preserves_prefix_and_tail`
- `string::mem::tests::test_memcpy_partial`
- `string::wide::tests::test_wmemcpy_basic`
- `string_properties::prop_memcpy_then_memcmp_is_zero`

Golden fixture SHA-256 values recorded during the proof:

- `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
- `tests/conformance/fixtures/memcpy_strict.json`: `6bdd6fb00bff508d07eb985bdc7c258a1a10f8ea96de72cf7e392483e886c233`

Isomorphism:

- Copied length remained `min(count, dest.len(), src.len())`.
- The candidate path ran only when the already-clamped count was exactly 4096.
- Destination bytes `0..4096` received exactly the same source bytes as the
  existing slice copy.
- Destination tail bytes were untouched.
- The path has no ordering comparison, tie-breaking, floating-point, or RNG
  behavior.

Local proof checks:

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs` passed.
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs .skill-loop-progress.md .beads/issues.jsonl` passed.

## Post Benchmark

RCH first routed one post run to `vmi1153651` despite the requested worker. That
run is recorded as non-comparable evidence only:

| Row | FrankenLibC p50 | FrankenLibC mean | FrankenLibC p95 | FrankenLibC p99 | host p50 | host mean | host p95 | host p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `memcpy_4096` | 111.400 ns | 132.154 ns | 173.628 ns | 261.000 ns | 68.838 ns | 77.879 ns | 118.688 ns | 158.962 ns |

Same-worker post benchmark on `vmi1152480`:

| Row | FrankenLibC p50 | FrankenLibC mean | FrankenLibC p95 | FrankenLibC p99 | host p50 | host mean | host p95 | host p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `memcpy_4096` | 39.619 ns | 51.880 ns | 65.000 ns | 78.880 ns | 29.894 ns | 32.555 ns | 37.824 ns | 65.000 ns |

Command:

```bash
env RCH_WORKER=vmi1152480 RCH_PREFERRED_WORKER=vmi1152480 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary AGENT_NAME=BoldFalcon RCH_BUILD_SLOTS=2 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd274-post-vmi1152480-retry cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memcpy_4096 --noplot --sample-size 35 --warm-up-time 1 --measurement-time 2
```

Target delta on `vmi1152480`:

- p50: `43.030 -> 39.619 ns` (`+7.9%`)
- mean: `45.624 -> 51.880 ns` (`-13.7%`)
- p95: `48.178 -> 65.000 ns` (`-35.1%`)
- p99: `70.000 -> 78.880 ns` (`-12.7%`)

## Verdict

Rejected and restored. The p50 win was real enough to record, but the mean and
tail regressions fail the Score >= 2.0 keep gate. Score: `0.0`.

Source restoration proof:

- Candidate code and proof-only test were removed.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs` passed.
- `git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs` passed.

Next route: stop exact 4096-byte manual portable-SIMD tile-copy work. The next
memcpy attempt needs a structurally different primitive, such as a no-overlap
ABI/slice classifier that lets Rust choose its best intrinsic path, or an
alignment-aware dual-stream copy strategy. Only start that after a fresh
profile-backed bead reproduces a real residual.
