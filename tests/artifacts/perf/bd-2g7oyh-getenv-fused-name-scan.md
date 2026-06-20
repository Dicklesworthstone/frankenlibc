# bd-2g7oyh getenv fused name scan

Date: 2026-06-20
Agent: BlackThrush / cod-a

## Lever

Targeted the deployed `getenv` residual loss from `strtol_glibc_bench` after the
parser rows had already been narrowed. The strict fast path previously scanned
the name once to find the NUL, then built a slice and ran `valid_env_name`
before walking `environ`. The candidate fuses NUL discovery and name validation
into one bounded scan, then walks `environ` by raw pointer/length so the name
bytes are not indexed through a slice in the inner compare.

The non-fast-path membrane route and the bootstrap-sensitive route stay on the
existing `native_getenv(&[u8])` implementation.

## Commands

Cargo rejected the requested `cargo bench --release` spelling for benchmarks:

```text
cargo bench --release
error: unexpected argument '--release' found
```

Benchmarks therefore used Cargo's optimized bench profile, per crate:

```bash
env AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 \
  rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
    --bench strtol_glibc_bench -- --noplot
```

Same-worker A/B used `vmi1227854` after `rch` ignored earlier worker selectors.
The paired runs used the same command and worker after temporarily restoring the
old source with `apply_patch` for the baseline, then reapplying the candidate.

## Same-worker result

Worker: `vmi1227854`

| Workload | Baseline FL | Baseline glibc | Baseline fl/glibc | Candidate FL | Candidate glibc | Candidate fl/glibc | FL old/new |
|---|---:|---:|---:|---:|---:|---:|---:|
| `getenv_hit` | 26.42 ns | 10.56 ns | 2.50x | 19.15 ns | 10.14 ns | 1.89x | 0.725x |
| `getenv_miss` | 36.10 ns | 13.58 ns | 2.66x | 27.66 ns | 14.68 ns | 1.88x | 0.766x |

Verdict: keep as a real same-worker gap cut. It is still a loss versus glibc,
but cuts the FrankenLibC deployed `getenv` hit row by 27.5% and miss row by
23.4%.

## Routing screens

Current-head broad baseline on `vmi1153651` showed the target gap:

| Workload | FL | glibc | fl/glibc |
|---|---:|---:|---:|
| `getenv_hit` | 85.65 ns | 30.78 ns | 2.78x |
| `getenv_miss` | 150.38 ns | 41.40 ns | 3.63x |

Candidate screens before the paired A/B:

| Worker | Workload | FL | glibc | fl/glibc | Use |
|---|---|---:|---:|---:|---|
| `vmi1293453` | `getenv_hit` | 50.54 ns | 32.12 ns | 1.57x | screen only |
| `vmi1293453` | `getenv_miss` | 96.11 ns | 37.92 ns | 2.53x | screen only |
| `vmi1152480` | `getenv_hit` | 37.13 ns | 16.89 ns | 2.20x | screen only |
| `vmi1152480` | `getenv_miss` | 61.71 ns | 25.76 ns | 2.40x | screen only |

## Qsort screen

The same session also added a `qsort_16_i32` bench row to test whether the old
small-qsort loss was still real. No qsort source change was made.

| Bench | Worker | FL | glibc | fl/glibc | Verdict |
|---|---|---:|---:|---:|---|
| `glibc_baseline_qsort_16_i32`, core only | `hz1` | 160.522 ns p50 | 244.160 ns p50 | 0.657x | WIN, no source lever |
| `glibc_baseline_qsort_16_i32`, `frankenlibc_abi` | `vmi1293453` | 12562.578 ns p50 | 12476.459 ns p50 | 1.007x | NEUTRAL, no source lever |

Action: keep the benchmark apparatus; no qsort implementation change.

## Validation

```bash
env AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 \
  rch exec -- cargo test -p frankenlibc-abi \
    --test conformance_diff_getenv --test metamorphic_getenv -- --nocapture
```

Result on `vmi1227854`: `conformance_diff_getenv` 2 passed / 0 failed;
`metamorphic_getenv` 9 passed / 0 failed.

```bash
env AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 \
  rch exec -- cargo build -p frankenlibc-abi --release
```

Result on `vmi1227854`: passed with pre-existing warnings.

Local checks:

```bash
git diff --check -- \
  crates/frankenlibc-abi/src/stdlib_abi.rs \
  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

Result: passed.

`rustfmt --edition 2024 --check` remains blocked by pre-existing formatting
drift outside this lever in `stdlib_abi.rs:454` and
`glibc_baseline_bench.rs:2851/2889`; not normalized in this perf commit.

## Next route

`getenv` still loses to glibc at 1.88x-1.89x after the fused scan. The next
credible lever is lower-cost environment lookup state, such as a generationed
name index or single-entry hot key cache with exact invalidation on
`setenv`/`putenv`/`unsetenv`, not another name-scan micro-tweak.
