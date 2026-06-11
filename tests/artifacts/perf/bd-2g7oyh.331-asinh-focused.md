# bd-2g7oyh.331 asinh focused gate

## Target

`bd-2g7oyh.331` targeted `glibc_baseline_math/asinh` after `br ready --json`
showed only peer-owned perf children:

- `bd-2g7oyh.125` / pow, assignee `MossyFern`
- `bd-2g7oyh.65` / strncmp, assignee `SilverCedar`

The route basis was the pass-59 broad RCH profile on actual worker
`vmi1227854`, which had shown an apparent unowned math residual:

- FrankenLibC p50 `790.616 ns`, mean `911.831 ns`
- host glibc p50 `736.592 ns`, mean `726.701 ns`

Pow lanes were excluded because they are peer-owned. Recent allocator and
string/memory rows were excluded unless a fresh focused gate reproduced a
material gap with a different primitive family.

## Focused RCH Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKERS=vmi1227854 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass59-asinh-baseline \
rch exec -- cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_math/asinh
```

Worker and result:

- RCH worker: `vmi1227854`
- RCH result: exit `0`, remote summary `240.5s`
- RCH selected the same worker as the broad routing profile.

Criterion interval output:

- FrankenLibC: `[913.17 ns 1.1365 us 1.2598 us]`
- host glibc: `[1.0124 us 1.0311 us 1.0534 us]`

`GLIBC_BASELINE_BENCH` sampled output:

- FrankenLibC: p50 `788.688 ns`, p95 `1265.307 ns`, p99 `1374.770 ns`,
  mean `858.628 ns`, throughput `998440.005 ops/s`
- host glibc: p50 `1016.759 ns`, p95 `1489.277 ns`, p99 `1767.968 ns`,
  mean `1090.638 ns`, throughput `902959.313 ops/s`

## Proof

No source edit was made. Behavior is unchanged by construction:

- `crates/frankenlibc-core/src/math/trig.rs` sha256:
  `d0d5ad79945010878a18b01a364a7730821a4e5567605eeca82bb1cac3fd827c`
- `crates/frankenlibc-abi/src/math_abi.rs` sha256:
  `d305aa7749d912ce496ef256010a11715c87c86cae80e8368a1a9d0de1a551de`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs` sha256:
  `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`
- `git diff --exit-code -- crates/frankenlibc-core/src/math/trig.rs crates/frankenlibc-abi/src/math_abi.rs crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`
  passed.
- Ordering, tie-breaking, finite/special floating-point behavior, errno
  handling, fixture outputs, and RNG behavior were not touched.

## Verdict

NO-CODE REJECTED, Score `0.0`.

The focused same-worker gate reversed the broad result. FrankenLibC was faster
than host glibc by both p50 and mean, so an `asinh` source edit would violate
the profile-backed target rule.

Next route: reprofile and pick a different reproduced unowned residual. Do not
add a medium-range `asinh` fast path unless a future focused gate reproduces a
material same-worker gap.
