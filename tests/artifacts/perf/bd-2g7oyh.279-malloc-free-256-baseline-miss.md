# bd-2g7oyh.279 malloc_free_256 baseline miss

## Target

- Bead: `bd-2g7oyh.279`
- Broad-profile source: pass-23 profile after `be249355`, RCH worker `vmi1227854`
- Broad row: `glibc_baseline_malloc_free_256/malloc_free_256`
- Broad signal: FrankenLibC median `6.065 ns/op` vs host glibc median `3.545 ns/op`

The broad row made `malloc_free_256` the top unowned clean residual after excluding peer-owned or peer-dirty string work.

## Focused Baseline

Clean detached worktree:

```text
/data/projects/.scratch/frankenlibc-bd279-baseline-c1dac519
HEAD c1dac5195377b0c623946774c7ad9dcaf8b1a762
```

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  RCH_ENV_ALLOWLIST=AGENT_NAME,FRANKENLIBC_BENCH_PIN,CARGO_BUILD_JOBS \
  AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_malloc_free_256' --noplot --sample-size 30 \
  --warm-up-time 1 --measurement-time 3
```

Result on RCH worker `ovh-a`:

```text
GLIBC_BASELINE_BENCH profile_id=malloc_free_256 impl=frankenlibc_core_state p50_ns_op=5.320 p95_ns_op=7.537 p99_ns_op=15.000 mean_ns_op=6.436
GLIBC_BASELINE_BENCH profile_id=malloc_free_256 impl=host_glibc p50_ns_op=4.815 p95_ns_op=10.000 p99_ns_op=15.000 mean_ns_op=6.002
```

Focused gap:

- p50 ratio: `1.10x`
- mean ratio: `1.07x`
- tails: not worse for FrankenLibC in the focused row

## Candidate Rejected Before Edit

Candidate lever was a 256-byte size-class certificate specialization mirroring the existing 64-byte hot certificate path in `crates/frankenlibc-core/src/malloc/allocator.rs`.

No source edit was made. With a focused same-worker gap of only `1.10x` median / `1.07x` mean, the lever cannot credibly clear the `Impact x Confidence / Effort >= 2.0` keep gate.

## Behavior Proof

No behavior changed:

- Source unchanged for allocator files.
- Ordering/LIFO/tie-breaking unchanged.
- Floating point and RNG not applicable.
- Golden lifecycle hashes unchanged by construction because no code was edited.

## Verdict

NO-CODE REJECTED, Score `0.0`.
