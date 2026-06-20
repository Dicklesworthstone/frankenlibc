# bd-2g7oyh.496 getenv hot-key cache

## Summary

Target: residual deployed strict `getenv_hit` / `getenv_miss` losses in
`strtol_glibc_bench` after the fused-name scanner had narrowed but not closed
the gap.

Lever kept: a single-entry thread-local hot-key cache for deployed strict
single-threaded `getenv`. The key is the exact requested name length plus the
first 16 bytes packed into two `u64`s. The cached value is guarded by
`ENVIRON_EPOCH`, which increments after successful `setenv`, `unsetenv`,
`putenv`, and `clearenv`. The cache is disabled in test builds and after
`__libc_single_threaded` flips to 0.

## Same-worker A/B

Worker: `vmi1152480`.

Baseline command:

```bash
env AGENT_NAME=cod-b BR_AGENT_NAME=cod-b RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1152480 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b/criterion-getenv-hot-cache-baseline rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench strtol_glibc_bench -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

Candidate command after cleanup:

```bash
env AGENT_NAME=cod-b BR_AGENT_NAME=cod-b RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1152480 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b/criterion-getenv-hot-cache-candidate-clean rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench strtol_glibc_bench -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

| Workload | Baseline FL | Baseline glibc | Baseline ratio | Candidate FL | Candidate glibc | Candidate ratio | FL old/new | Verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `getenv_hit` | 41.20 ns | 17.21 ns | 2.39x | 12.43 ns | 15.93 ns | 0.78x | 0.302x | WIN |
| `getenv_miss` | 64.90 ns | 25.60 ns | 2.53x | 21.45 ns | 23.34 ns | 0.92x | 0.330x | WIN |

The target rows moved from clear losses to glibc wins. Keep.

## Full final bench rows

Final candidate `strtol_glibc_bench` rows on `vmi1152480`:

| Workload | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `strtol_dec_short` | 8.75 ns | 9.41 ns | 0.93x | WIN |
| `strtol_dec_long` | 22.67 ns | 18.40 ns | 1.23x | LOSS |
| `strtol_hex` | 22.48 ns | 19.69 ns | 1.14x | LOSS |
| `atoi_short` | 4.27 ns | 11.90 ns | 0.36x | WIN |
| `atoi_long` | 11.39 ns | 21.11 ns | 0.54x | WIN |
| `atol_short` | 4.04 ns | 10.72 ns | 0.38x | WIN |
| `atol_long` | 10.77 ns | 20.53 ns | 0.52x | WIN |
| `atoll_short` | 4.07 ns | 10.57 ns | 0.38x | WIN |
| `atoll_long` | 11.37 ns | 20.08 ns | 0.57x | WIN |
| `strtod_int` | 12.73 ns | 39.97 ns | 0.32x | WIN |
| `strtod_simple` | 71.46 ns | 71.56 ns | 1.00x | NEUTRAL |
| `strtod_sci` | 22.69 ns | 48.10 ns | 0.47x | WIN |
| `rand` | 3.71 ns | 5.03 ns | 0.74x | WIN |
| `getenv_hit` | 12.43 ns | 15.93 ns | 0.78x | WIN |
| `getenv_miss` | 21.45 ns | 23.34 ns | 0.92x | WIN |
| `clock_gettime` | 35.45 ns | 26.28 ns | 1.35x | LOSS |
| `time` | 4.05 ns | 2.43 ns | 1.66x | LOSS |
| `pthread_self` | 1.90 ns | 2.00 ns | 0.95x | WIN |

Residual routed losses from this run: long/hex `strtol`, `clock_gettime`, and
`time`. `strtod_simple` is neutral. The getenv residual is closed for this
single-threaded repeated-key workload; cold, long-name, and multithreaded
environment workloads are separate profiles.

## Validation

Local:

```bash
env AGENT_NAME=cod-b BR_AGENT_NAME=cod-b CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-abi --lib
env AGENT_NAME=cod-b BR_AGENT_NAME=cod-b CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo test -p frankenlibc-abi --test conformance_diff_getenv --test metamorphic_getenv -- --nocapture
rustfmt --edition 2024 --check crates/frankenlibc-abi/src/stdlib_abi.rs
git diff --check
```

Results: `cargo check -p frankenlibc-abi --lib` passed with known pre-existing
warnings; local `conformance_diff_getenv` passed 2/0; local
`metamorphic_getenv` passed 9/0; touched-file rustfmt passed; `git diff
--check` passed.

Remote:

```bash
env AGENT_NAME=cod-b BR_AGENT_NAME=cod-b RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1152480 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo build -p frankenlibc-abi --release
env AGENT_NAME=cod-b BR_AGENT_NAME=cod-b RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1152480 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo test -p frankenlibc-abi --test conformance_diff_getenv --test metamorphic_getenv -- --nocapture
```

Results: release build passed on `vmi1152480`; focused conformance passed on
`vmi1227854` after rch routed away from the preferred worker
(`conformance_diff_getenv` 2/0, `metamorphic_getenv` 9/0).

Known unrelated blockers: `cargo fmt --check -p frankenlibc-abi` is blocked by
pre-existing crate-wide formatting drift outside this getenv file.
`cargo check -p frankenlibc-abi --all-targets` was rerun and remains blocked by
the pre-existing scratch test `crates/frankenlibc-abi/tests/zz_scratch_divmin.rs`,
whose `CDiv`/`CLdiv`/`CLldiv` assertions lack `PartialEq`/`Debug`.

## Decision

Keep the source change. Do not retry further name-scan micro-tweaks for this
hot repeated-key workload. Next residual targets from the final bench are
`clock_gettime`, `time`, and long/hex `strtol`; any future environment work
should profile cold lookup, long names, or multithreaded mutation/read patterns
instead of the now-closed single-threaded hot key path.
