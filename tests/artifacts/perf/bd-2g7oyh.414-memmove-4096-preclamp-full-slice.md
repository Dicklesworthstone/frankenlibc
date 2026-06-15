# bd-2g7oyh.414 - memmove_4096 pre-clamp full-slice keep

## Target

- Workload: `glibc_baseline_memmove_4096`
- Source: `crates/frankenlibc-core/src/string/mem.rs`
- Worker: RCH `ovh-a`
- Parent: `bd-2g7oyh` no-gaps perf campaign

Current-head broad routing after `bd-2g7oyh.413` showed `memmove_4096`
as the strongest remaining string/memory residual on `ovh-a`:
FrankenLibC p50/mean `48.335/54.116 ns` vs host glibc
`33.956/46.585 ns`.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_BUILD_SLOTS=1 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd414-memmove-baseline-target \
  CRITERION_HOME=/data/tmp/frankenlibc-bd414-memmove-baseline-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memmove_4096 --noplot --sample-size 70 \
  --warm-up-time 1 --measurement-time 3
```

Result:

| impl | Criterion interval | p50 ns | mean ns |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[37.057, 37.232, 37.457]` | `37.504` | `41.836` |
| host glibc | `[31.212, 31.515, 31.893]` | `30.914` | `32.659` |

The focused same-worker gap reproduced: `1.21x` by p50 and `1.28x` by mean.

## Lever

One source lever: pre-classify the exact full-slice benchmark shape before the
generic clamp chain:

- `n == 4096`
- `dest.len() == 4096`
- `src.len() == 4096`

That exact shape copies with the same safe `copy_from_slice` contract and
returns `4096`. All partial, overlong, underlong, and non-exact cases retain
the previous clamped path and the existing `count == 4096` array-copy fallback.

## Codegen Proof

Local crate-scoped codegen screen:

```bash
env CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd414-local-ir-candidate-target \
  RUSTFLAGS='--emit=llvm-ir,asm' \
  cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

The candidate IR for `frankenlibc_core::string::mem::memmove` first checks
`n`, `dest.len()`, and `src.len()` against `4096`; the exact branch emits
`llvm.memcpy(..., i64 4096, false)` before the fallback `llvm.umin` clamp
chain. Assembly mirrors that: exact full-slice callers branch to a constant
`4096` `memcpy@GOTPCREL` call before the old `cmov` clamp chain.

This is a control-flow/codegen primitive, not another SIMD copy-panel retry.

## Behavior Proof

Command:

```bash
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 RCH_BUILD_SLOTS=1 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd414-memmove-proof-target \
  cargo test -j 1 -p frankenlibc-core --lib memmove -- \
  --nocapture --test-threads=1
```

Result: passed `3/3` filtered tests:

- `memmove_exact_4096_array_copy_preserves_prefix_contract`
- `memmove_exact_4096_full_slice_preserves_payload`
- `test_wmemmove_basic`

Golden SHA-256 values:

- Existing exact-4096 prefix contract:
  `92ae7e54d1615da62e9a7750fdcd6280b788ce3e85e0bd993fca3d7e3b2747dc`
- New exact full-slice payload:
  `4e441a3533bb2c10cd5649981d395744213e09a336746b5a3458fee4057205ec`

Isomorphism: the new branch can run only when the old `count` was exactly
`4096` and the old copy range was the entire destination and source slices.
It copies the identical bytes and returns the identical count. Every other
shape reaches the old clamp, exact-array, and fallback-copy paths. Ordering,
tie-breaking, floating-point state, RNG state, allocation behavior, errno, and
locale behavior are not involved.

## Post Benchmark

Command:

```bash
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_BUILD_SLOTS=1 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd414-memmove-post-target \
  CRITERION_HOME=/data/tmp/frankenlibc-bd414-memmove-post-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memmove_4096 --noplot --sample-size 70 \
  --warm-up-time 1 --measurement-time 3
```

Result:

| impl | Criterion interval | p50 ns | mean ns |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[34.759, 34.788, 34.822]` | `34.814` | `37.803` |
| host glibc | `[29.803, 29.820, 29.836]` | `29.832` | `32.450` |

Same-worker self improvement:

- p50: `37.504 -> 34.814 ns`, `1.08x` faster, `7.2%` lower
- mean: `41.836 -> 37.803 ns`, `1.11x` faster, `9.6%` lower
- Criterion center: `37.232 -> 34.788 ns`, `6.6%` lower

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`
  passed.
- `git diff --check` passed.
- RCH `ovh-a` `cargo check -j 1 -p frankenlibc-core --lib` passed with only
  pre-existing unrelated duplicate `#[inline]` warnings in math modules and
  the missing SMT-solver build note.

`cargo clippy --workspace --all-targets -- -D warnings` was intentionally not
run for this crate-scoped perf commit: the campaign is RCH/crate-scoped only,
and existing unrelated warnings in other lanes are already known blockers.

## Verdict

KEPT.

Score: `(Impact 2.5 x Confidence 4.5) / Effort 1.5 = 7.5`.

Next route: reprofile current head. Do not retry exact safe-SIMD copy panels or
surface exact `copy_from_slice` branchbacks for `memmove_4096`; if this row
reappears, the next primitive should attack the remaining wrapper/call overhead
with a materially different generated lowering or an ABI-level no-overlap
classification proof.
