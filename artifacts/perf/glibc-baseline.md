# Host glibc baseline profile

Bead: `bd-bp8fl.8.3`  
Generated: `2026-05-03T02:54Z`  
Source base commit: `0f2534c5` plus the uncommitted `bd-bp8fl.8.3` benchmark/report diff  
Profile tool: Criterion via `rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- --quiet`  
Target dir: `/data/tmp/cargo-target-frankenlibc-bd-bp8fl-8-3-rchbench2`  
Runtime mode: `strict`  
Replacement level: `L0`

## Scope

This first host baseline covers the top ported libc hot-path families that are already central in the repo benchmark surface:

| API family | Symbols | Workload |
|---|---|---|
| `string` | `memcpy`, `memset`, `strlen`, `strcmp` | fixed-size copy/fill/scans over 256-4096 byte inputs |
| `malloc` | `malloc/free` | 64 byte allocate/free cycle |
| `stdlib` | `qsort` | 128 `i32` reverse-ish input |

The FrankenLibC side uses `frankenlibc-core` implementations where possible so host glibc calls made through the `libc` crate cannot be accidentally resolved to ABI-exported FrankenLibC symbols in the same benchmark binary. The allocator row is explicitly `frankenlibc_core_state`: it measures core allocator state routing and lifecycle overhead with a synthetic backend, not the final ABI `malloc` path.

## Ranked Hot Paths

`Hotness` is the host-comparison pressure score for this micro-profile: `frankenlibc_mean_ns_op / host_glibc_mean_ns_op`. Rows are sorted by that score.

| Rank | Profile | API family | Symbol | Workload | FrankenLibC mean ns/op | host glibc mean ns/op | Hotness | Samples | Parity proof ref |
|---:|---|---|---|---|---:|---:|---:|---:|---|
| 1 | `malloc_free_64` | `malloc` | `malloc/free` | 64 byte allocate-free cycle | 24401.148 | 9.283 | 2628.59x | 21 / 35 | `crates/frankenlibc-core/src/malloc` |
| 2 | `strlen_4096` | `string` | `strlen` | 4096 byte NUL scan | 1066.471 | 24.484 | 43.56x | 27 / 33 | `tests/conformance/fixtures/string_ops` |
| 3 | `strcmp_256_equal` | `string` | `strcmp` | equal 256 byte strings | 209.020 | 10.660 | 19.61x | 29 / 34 | `tests/conformance/fixtures/string_ops` |
| 4 | `memcpy_4096` | `string` | `memcpy` | 4096 byte copy | 47.184 | 39.053 | 1.21x | 32 / 32 | `tests/conformance/fixtures/string_memory_full` |
| 5 | `qsort_128_i32` | `stdlib` | `qsort` | 128 i32 reverse-ish input | 2614.674 | 2624.969 | 1.00x | 26 / 26 | `crates/frankenlibc-core/src/stdlib/sort.rs` |
| 6 | `memset_4096` | `string` | `memset` | 4096 byte fill | 37.016 | 37.286 | 0.99x | 32 / 32 | `tests/conformance/fixtures/string_memory_full` |

## Raw Criterion Rows

```text
GLIBC_BASELINE_BENCH profile_id=memcpy_4096 impl=frankenlibc_core api_family=string symbol=memcpy workload="4096 byte copy" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=32 p50_ns_op=46.133 p95_ns_op=55.000 p99_ns_op=220.000 mean_ns_op=47.184 throughput_ops_s=30178588.205 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=tests/conformance/fixtures/string_memory_full
GLIBC_BASELINE_BENCH profile_id=memcpy_4096 impl=host_glibc api_family=string symbol=memcpy workload="4096 byte copy" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=32 p50_ns_op=36.398 p95_ns_op=42.500 p99_ns_op=130.000 mean_ns_op=39.053 throughput_ops_s=30389129.737 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=tests/conformance/fixtures/string_memory_full
GLIBC_BASELINE_BENCH profile_id=memset_4096 impl=frankenlibc_core api_family=string symbol=memset workload="4096 byte fill" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=32 p50_ns_op=35.431 p95_ns_op=42.500 p99_ns_op=80.000 mean_ns_op=37.016 throughput_ops_s=29637872.601 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=tests/conformance/fixtures/string_memory_full
GLIBC_BASELINE_BENCH profile_id=memset_4096 impl=host_glibc api_family=string symbol=memset workload="4096 byte fill" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=32 p50_ns_op=35.867 p95_ns_op=40.885 p99_ns_op=90.000 mean_ns_op=37.286 throughput_ops_s=29791934.705 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=tests/conformance/fixtures/string_memory_full
GLIBC_BASELINE_BENCH profile_id=strlen_4096 impl=frankenlibc_core api_family=string symbol=strlen workload="4096 byte NUL scan" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=27 p50_ns_op=1073.594 p95_ns_op=1176.540 p99_ns_op=1250.024 mean_ns_op=1066.471 throughput_ops_s=1001458.306 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=tests/conformance/fixtures/string_ops
GLIBC_BASELINE_BENCH profile_id=strlen_4096 impl=host_glibc api_family=string symbol=strlen workload="4096 byte NUL scan" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=33 p50_ns_op=21.342 p95_ns_op=32.750 p99_ns_op=90.000 mean_ns_op=24.484 throughput_ops_s=51242242.965 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=tests/conformance/fixtures/string_ops
GLIBC_BASELINE_BENCH profile_id=strcmp_256_equal impl=frankenlibc_core api_family=string symbol=strcmp workload="equal 256 byte strings" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=29 p50_ns_op=208.680 p95_ns_op=245.500 p99_ns_op=271.000 mean_ns_op=209.020 throughput_ops_s=5198422.327 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=tests/conformance/fixtures/string_ops
GLIBC_BASELINE_BENCH profile_id=strcmp_256_equal impl=host_glibc api_family=string symbol=strcmp workload="equal 256 byte strings" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=34 p50_ns_op=7.790 p95_ns_op=17.500 p99_ns_op=90.000 mean_ns_op=10.660 throughput_ops_s=168310851.501 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=tests/conformance/fixtures/string_ops
GLIBC_BASELINE_BENCH profile_id=malloc_free_64 impl=frankenlibc_core_state api_family=malloc symbol=malloc/free workload="64 byte allocate-free cycle" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=21 p50_ns_op=1897.797 p95_ns_op=101311.119 p99_ns_op=101632.908 mean_ns_op=24401.148 throughput_ops_s=19677.414 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=crates/frankenlibc-core/src/malloc
GLIBC_BASELINE_BENCH profile_id=malloc_free_64 impl=host_glibc api_family=malloc symbol=malloc/free workload="64 byte allocate-free cycle" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=35 p50_ns_op=5.705 p95_ns_op=20.000 p99_ns_op=70.000 mean_ns_op=9.283 throughput_ops_s=189859938.236 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=crates/frankenlibc-core/src/malloc
GLIBC_BASELINE_BENCH profile_id=qsort_128_i32 impl=frankenlibc_core api_family=stdlib symbol=qsort workload="128 i32 reverse-ish input" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=26 p50_ns_op=2651.479 p95_ns_op=3006.000 p99_ns_op=3009.484 mean_ns_op=2614.674 throughput_ops_s=401570.117 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=crates/frankenlibc-core/src/stdlib/sort.rs
GLIBC_BASELINE_BENCH profile_id=qsort_128_i32 impl=host_glibc api_family=stdlib symbol=qsort workload="128 i32 reverse-ish input" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=26 p50_ns_op=2649.375 p95_ns_op=2831.188 p99_ns_op=4228.000 mean_ns_op=2624.969 throughput_ops_s=414630.102 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=crates/frankenlibc-core/src/stdlib/sort.rs
```

## Follow-Up Optimization Beads

1. `strlen_4096`: specialize long NUL scans with word-at-a-time or vectorized scanning after keeping fixture parity green.
2. `strcmp_256_equal`: add a wide compare path for equal/long-prefix strings, with signed-difference parity tests for mismatch boundaries.
3. `malloc_free_64`: split allocator metadata/lifecycle-log cost from real ABI allocation cost before optimizing; this row currently measures core state routing with synthetic backend, so it should drive a sharper allocator-profile bead rather than an immediate hot-path rewrite.

## Validation Commands

```bash
bash -n scripts/perf/glibc_baseline.sh
CARGO_TARGET_DIR=/data/tmp/cargo-target-frankenlibc-bd-bp8fl-8-3-test RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR rch exec -- cargo test -p frankenlibc-bench --lib
CARGO_TARGET_DIR=/data/tmp/cargo-target-frankenlibc-bd-bp8fl-8-3-rchbench2 RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- --quiet
```
