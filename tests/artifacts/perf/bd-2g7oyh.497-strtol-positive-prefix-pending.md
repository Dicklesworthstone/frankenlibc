# bd-2g7oyh.497 strtol positive digit-prefix final verification

## Bead

- ID: `bd-2g7oyh.497`
- Title: `perf: strtol positive digit-prefix fast path pending bench`
- Verification owner: `cod-a` / `BlackThrush`
- Source commit: `6f311ef07` (`perf(stdlib): fast-path strtol positive prefixes`)
- Status after verification: keep

## Lever

`parse_strtol_c_string_fast` already handled deployed strict-mode base-10 and
base-16 `strtol` without the generic core parser. Commit `6f311ef07` split out
the hottest positive-prefix cases:

- base 10, first byte is `0..9`;
- base 16, first byte is a hex digit, including the `0x`/`0X` prefix when it
  is followed by at least one hex digit.

Those paths parse directly from the initial cursor and skip the generic
whitespace/sign/base setup. Signed, whitespace-prefixed, invalid-base, and
non-10/16 cases still take the existing path.

## Benchmark

Baseline and candidate used the same remote worker:

```text
worker: vmi1152480
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a
bench: cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench strtol_glibc_bench -- --noplot --sample-size 10 \
  --warm-up-time 1 --measurement-time 2
```

| Workload | Baseline FL | Baseline glibc | Baseline ratio | Candidate FL | Candidate glibc | Candidate ratio | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| `strtol_dec_short` | 9.35 ns | 9.72 ns | 0.96x | 4.64 ns | 9.33 ns | 0.50x | WIN |
| `strtol_dec_long` | 25.21 ns | 20.88 ns | 1.21x | 9.95 ns | 17.38 ns | 0.57x | WIN |
| `strtol_hex` | 21.55 ns | 19.04 ns | 1.13x | 13.52 ns | 17.30 ns | 0.78x | WIN |

The candidate also kept the already-green parser rows green in the same final
run. Remaining red rows are not caused by this lever:

| Workload | Candidate FL | Candidate glibc | Ratio | Route |
|---|---:|---:|---:|---|
| `clock_gettime` | 34.95 ns | 26.24 ns | 1.33x | Separate timing primitive; do not retry the rejected vDSO pointer-cache family. |
| `time` | 4.12 ns | 2.51 ns | 1.64x | Separate timing primitive. |
| `pthread_self` | 1.91 ns | 1.73 ns | 1.10x | Separate TLS/ABI entrypoint route if stable on a focused run. |

## Validation

Passed:

- touched-file `rustfmt --edition 2024 --check crates/frankenlibc-abi/src/stdlib_abi.rs`;
- `git diff --check -- crates/frankenlibc-abi/src/stdlib_abi.rs`;
- rch `cargo test -j 1 -p frankenlibc-abi --test conformance_strtol_family -- --nocapture --test-threads=1`;
- rch `cargo test -j 1 -p frankenlibc-abi --test strtol_family_differential_fuzz -- --nocapture --test-threads=1` with 1,000,000 comparisons and 0 divergences vs host glibc;
- rch `cargo check -j 1 -p frankenlibc-abi --lib`;
- rch `cargo build -j 1 -p frankenlibc-abi --release`.

Blocked:

- rch `cargo clippy -j 1 -p frankenlibc-abi --lib -- -D warnings` failed
  before analysis because `cargo-clippy` is not installed for
  `nightly-2026-04-28-x86_64-unknown-linux-gnu`.

## Verdict

Keep. The code-first fast path converts all three target `strtol` rows into
host-glibc wins on same-worker remote evidence and keeps the strtol
conformance/fuzz gate green.
