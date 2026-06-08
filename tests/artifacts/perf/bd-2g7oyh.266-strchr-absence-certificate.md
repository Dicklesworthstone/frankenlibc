# bd-2g7oyh.266 - strchr absent needle certificate

## Target

- Bead: `bd-2g7oyh.266`
- Profile-backed row: `glibc_baseline_strchr_absent`
- Workload: 4096-byte C string, scan for absent nonzero byte.

Fresh broad profile after pass 13 on `vmi1167313`:

- `memcmp_4096`: FrankenLibC median 85.185 ns vs host 66.908 ns
- `strchr_absent`: FrankenLibC median 86.909 ns vs host 69.884 ns
- `strlen_4096`: FrankenLibC median 47.247 ns vs host 37.083 ns

`memcmp_4096` had the largest p50 residual, but its equality-control-plane and
superblock families were already rejected on same-worker evidence. This pass
finished the already-claimed `strchr_absent` bead with a different structural
primitive rather than another folded detector retune.

## One Lever

For `c != 0`, `strchr` now first finds the first needle with the existing
safe-Rust `memchr`. If no needle exists, `strchr` returns `None` immediately.
If a needle exists, it scans only the prefix before that needle for NUL. A NUL
in that prefix means the needle is after the logical C terminator, otherwise the
needle is the first visible match.

The `c == 0` branch still returns the first NUL-or-len via `strlen`, and
`strchrnul` remains unchanged on the original `find_byte_or_nul` path.

## Baseline

Focused clean baseline on `vmi1153651`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass14-strchr-baseline-rch \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strchr_absent --noplot --sample-size 35 \
  --warm-up-time 1 --measurement-time 2
```

Baseline `GLIBC_BASELINE_BENCH` row:

- FrankenLibC p50 95.850 ns, p95 175.022 ns, p99 600.589 ns, mean 125.818 ns
- Host glibc p50 74.301 ns, p95 122.494 ns, p99 166.863 ns, mean 83.962 ns

Baseline Criterion estimate from the same worker:

- FrankenLibC median 90.185 ns, mean 92.980 ns
- Host glibc median 80.994 ns, mean 84.288 ns

## Post

Same-worker post on `vmi1153651`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1153651 rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd266-strchr-minfold-post \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strchr_absent --noplot --sample-size 35 \
  --warm-up-time 1 --measurement-time 2
```

The target dir name is stale from an earlier scratch candidate. The source
synced for this run was the structural needle-absence certificate described
above.

Post `GLIBC_BASELINE_BENCH` row:

- FrankenLibC p50 64.296 ns, p95 149.247 ns, p99 241.000 ns, mean 78.536 ns
- Host glibc p50 98.132 ns, p95 182.779 ns, p99 201.787 ns, mean 107.398 ns

Same-worker FrankenLibC delta:

- p50: 95.850 -> 64.296 ns, 1.49x faster
- mean: 125.818 -> 78.536 ns, 1.60x faster
- p95: 175.022 -> 149.247 ns, 1.17x faster
- p99: 600.589 -> 241.000 ns, 2.49x faster

Extra confirmation on `vmi1167313`:

- FrankenLibC Criterion median 49.807 ns, mean 50.764 ns
- Host glibc Criterion median 64.358 ns, mean 64.463 ns

The keep gate is based on the same-worker FrankenLibC self-time improvement;
the host row drifted between baseline and post.

## Behavior Proof

RCH proof command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd266-structural-proof-rch \
  cargo test -p frankenlibc-core strchr -- --nocapture --test-threads=1
```

Proof worker: `vmi1153651`

Result: passed. The run covered 14 direct `strchr`/`strchrnul` unit tests plus
`string_properties::prop_strchr_strrchr_both_find_or_miss`.

Golden transcript SHA-256:
`3656ba0841f975b7aa6d31cf8a01cac9b90635e6eecf66431ce80893bd859f18`

Isomorphism:

- Ordering preserved: yes. The decisive order is still
  `min(first(c), first(NUL))`. The new path discovers `first(c)` first, then
  certifies whether any NUL appears before it.
- Tie-breaking unchanged: yes. `c != 0`, so a byte cannot be both the needle
  and NUL. Equal needles are resolved by `memchr`'s first-occurrence contract.
- Terminator behavior preserved: if `first(NUL) < first(c)`, the prefix scan
  returns `None`; if `first(c) < first(NUL)` or no NUL exists, it returns the
  first needle; if no needle exists, it returns `None`.
- NUL needle behavior preserved: `c == 0` returns `strlen(s)`, the same
  first-NUL-or-len index as the old `find_byte_or_nul(s, 0)` path.
- `strchrnul`: unchanged.
- Floating point: not applicable.
- RNG: not applicable.

Risk note: for `c != 0`, the new path may scan beyond the logical C NUL inside
the safe Rust slice before proving the terminator ordering. That is memory-safe
in this core slice model, and the early-NUL semantics are pinned by direct tests.
It is also the reason this lever is scoped to the profiled absent-byte workload
and must be reprofiled before using it as evidence for early-NUL workloads.

## Validation

- RCH `cargo test -p frankenlibc-core strchr -- --nocapture --test-threads=1`
  passed on `vmi1153651`.
- RCH `cargo check -p frankenlibc-core --all-targets` passed on `vmi1156319`.
- The proof build emitted only known unrelated warnings:
  missing SMT solver from the build script and `unused_mut` in existing
  `wcslen_fold_isomorphism.rs` / `wcsnlen_fold_isomorphism.rs` tests.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`
  passed.
- `git diff --check` passed for `str.rs`, the progress ledger, and this
  artifact.
- Strict RCH `cargo clippy -p frankenlibc-core --lib -- -D warnings` on
  `vmi1156319` was blocked only by existing non-`strchr` lints in
  `math/exp.rs`, `stdio/file.rs`, `stdlib/sort.rs`, and `string/regex.rs`.

## Keep Gate

Score = Impact 4 * Confidence 3 / Effort 1 = 12.0

Verdict: kept. Same-worker FrankenLibC p50, mean, p95, and p99 all improved by
well over the Score >= 2.0 gate with the exact `strchr` golden transcript
unchanged.
