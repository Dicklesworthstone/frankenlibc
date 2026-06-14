# bd-jc3vp4 malloc_cache_pressure_256 focused gate

## Target

- Bead: `bd-jc3vp4`
- Profile: `glibc_baseline_malloc_cache_pressure_256`
- Purpose: replace the one-live `malloc_free_64/256` routing row with a deeper allocator gate that allocates and frees `MAGAZINE_CAPACITY + 1` 256-byte objects, then reallocates and frees the same count again.
- Primitive family under consideration: alien-graveyard section 7.9, modern allocator design (mimalloc/TLSF/slab), only if the deeper path reproduced a material same-worker gap.

## Benchmark Scaffold

One benchmark-only gate was added to `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`:

- `PRESSURE_OBJECTS = MAGAZINE_CAPACITY + 1 = 65`
- FrankenLibC side: one persistent `MallocState`, synthetic monotone backend pointers, allocate 65, free 65, allocate 65, free 65.
- Host side: paired `libc::malloc(256)` / `libc::free` over the same 65 + 65 object shape.
- This reaches hot-slot, thread-cache magazine, and central-bin spill/refill behavior; it is not the one-live hot-slot-only benchmark closed in `bd-2g7oyh.404`.

The shared benchmark file byte-matches the clean RCH worktree version:

```text
bench sha256 c2dd8cd2419275d222c57aac19b86b72d8d61369c31026a44f929f905200e67c
cmp shared-vs-clean benchmark: match
```

## Remote Baseline

Clean worktree:

```text
/data/projects/.scratch/frankenlibc-bd-jc3vp4-work-20260614T2312
HEAD 8c7793e53 fix(lround family): exception-free conversion (no spurious FE_INEXACT)
```

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 \
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-jc3vp4-clean-baseline-target-20260614T2314 \
CRITERION_HOME=/data/tmp/frankenlibc-bd-jc3vp4-clean-baseline-criterion-20260614T2314 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_malloc_cache_pressure_256 \
--noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

RCH selected worker `vmi1153651` and completed remotely.

Results:

| impl | criterion interval | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC `MallocState` | `[1.5470 us 1.6390 us 1.7725 us]` | `1550.529` | `2284.000` | `3659.814` | `1615.113` |
| host glibc | `[6.1254 us 6.3842 us 6.7282 us]` | `6033.063` | `7324.000` | `8719.470` | `6260.367` |

FrankenLibC is faster on this deeper gate by `3.89x` p50 and `3.88x` mean.

## Behavior Proof

No allocator source lever was attempted.

Clean-source SHAs used by the RCH baseline:

```text
allocator.rs   4817d9da746ae05c863006bbc7523ed6d1dfb17e38129b2a8a7c23a04b38b45e
thread_cache.rs 4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174
size_class.rs  e267398a2ef69ed24c3adf3a23fe82ccea0a01a54d5fb93c3c48b07fff9dadef
```

Isomorphism obligations:

- Allocation/free ordering: benchmark order is fixed as allocate-all, free-all, allocate-all, free-all.
- Hot-slot LIFO, magazine displacement, central-bin spill/refill, active_count, and total_allocated: allocator source unchanged, so existing semantics are unchanged by construction.
- Tie-breaking: no allocator ordering branch changed.
- Floating-point and RNG: not applicable.
- Golden-output sha256: no allocator golden changed because no allocator implementation changed; the benchmark file SHA above pins the new measurement harness.

Validation:

```text
git diff --check -- crates/frankenlibc-bench/benches/glibc_baseline_bench.rs: pass
rustfmt --edition 2024 --check crates/frankenlibc-bench/benches/glibc_baseline_bench.rs: pass
RCH cargo bench compiled and ran the new benchmark: pass
```

## Verdict

No source optimization is profile-backed for allocator on this deeper route. The next allocator primitive should not be applied to this benchmark unless a future current-head focused gate reverses and shows a material same-worker gap.

Allocator source lever: not attempted. Score `0.0` for source optimization because there is no gap to optimize on this gate.

Next route: reprofile current head and attack the next reproduced residual. Based on the Pass 106 broad profile, the pending non-allocator candidates are string/codegen rows such as `memcmp_4096`, `memmove_4096`, `memchr_absent`, `strncasecmp_256_equal`, and `powf_irrational`, with prior no-retry families respected.
