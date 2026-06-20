# bd-f874go - strict allocator native reentry-slot reuse - MEASURED KEEP

**Lever:** reuse the already-acquired public allocator `AllocatorReentryGuard`
slot when the strict host allocator path calls the native host `calloc`/`free`
trampolines. The old path acquired the public allocator guard, then called
`current_allocator_reentry_slot()` again inside `native_libc_calloc` or
`native_libc_free` before setting the native reentry bit. The kept path threads
the public guard's slot into `native_libc_calloc_with_slot` and
`native_libc_free_with_slot`.

**Why it is safe:** the public guard proves the thread owns a stable
`AllocatorReentrySlot` for the duration of the allocator call. Reusing that slot
for the nested native guard preserves the same atomic native guard-bit protocol;
only the redundant slot lookup is removed. Bootstrap/reentrant paths still fall
back to the existing bump/bootstrap behavior.

**Verdict:** KEEP as a measured deployed-allocator fast-path reduction. It does
not close allocator dominance versus glibc; it materially narrows the same-worker
256 B, 256 KiB, and 1 MiB gaps and leaves the largest deployed 4 MiB row neutral
in absolute FrankenLibC time. The 16 B row is a slight loss/noise row and the
4 KiB row improves absolute FrankenLibC time but not the normalized ratio because
the glibc arm also sped up in that run.

## Method

Benchmark command, per-crate:

```sh
AGENT_NAME=cod-b \
RCH_REQUIRE_REMOTE=1 \
RCH_TEST_SLOTS=1 \
RCH_BUILD_SLOTS=1 \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
rch exec -- env AGENT_NAME=cod-b FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  cargo bench -p frankenlibc-bench --features abi-bench \
  --bench calloc_glibc_bench -- --measurement-time 2 --warm-up-time 1 --noplot
```

`rch` selected worker `vmi1152480` for both the baseline and candidate proof
runs, with the same worker-scoped target pool
`.rch-target-vmi1152480-pool-250596d7f71ad30a73c5092e37814573`.

Comparator arms:

- `fl`: deployed `frankenlibc_abi::malloc_abi::calloc(1, n)` + `free`.
- `fl_old`: `malloc(n)` + explicit zero write + `free`.
- `fl_native`: bare main-namespace host glibc `calloc`/`free` reached through
  FrankenLibC's native probe, with no membrane bookkeeping.
- `glibc`: pristine isolated host glibc `calloc`/`free` resolved through
  `dlmopen(LM_ID_NEWLM, "libc.so.6")`.

## Results

p50 ns/op, alloc+free cycle. `ratio` is `fl / glibc` in the same run; lower is
better and `<1` means FrankenLibC beats glibc.

| size | baseline fl | baseline glibc | baseline ratio | candidate fl | candidate glibc | candidate ratio | fl new/base | verdict vs glibc | action |
|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 16 B | 85.087 | 7.230 | 11.77x | 86.020 | 7.148 | 12.03x | 1.011x | LOSS | Keep overall, but this row is negative evidence. |
| 256 B | 454.890 | 23.275 | 19.55x | 237.286 | 21.068 | 11.26x | 0.522x | LOSS vs glibc / WIN vs baseline | Keep; biggest small-allocation gap improved 47.8%. |
| 4096 B | 446.897 | 81.206 | 5.50x | 273.946 | 47.993 | 5.71x | 0.613x | LOSS vs glibc / ratio neutral-loss | Keep overall; absolute FrankenLibC p50 improved 38.7%, ratio worsened because glibc also sped up. |
| 65536 B | 903.792 | 526.206 | 1.72x | 711.313 | 430.895 | 1.65x | 0.787x | LOSS vs glibc / WIN vs baseline | Keep. |
| 262144 B | 2911.750 | 1644.329 | 1.77x | 1862.715 | 1561.114 | 1.19x | 0.640x | LOSS vs glibc / WIN vs baseline | Keep; normalized gap narrowed sharply. |
| 1048576 B | 14664.400 | 9440.443 | 1.55x | 10027.183 | 9393.547 | 1.07x | 0.684x | LOSS by strict 1.05 cutoff / near parity | Keep; near-parity after 31.6% absolute speedup. |
| 4194304 B | 47376.372 | 48195.740 | 0.98x | 47365.083 | 67326.391 | 0.70x | 1.000x | WIN vs glibc / neutral vs baseline | Keep; deployed FrankenLibC did not regress at the largest size. |

Candidate `fl_native / glibc` ratios were 23.78x, 8.71x, 4.63x, 1.44x,
1.13x, 1.07x, and 0.97x across the same size order. That keeps the previous
methodology conclusion intact: a large part of the headline glibc gap is still
the busy main-namespace host allocator versus the isolated `dlmopen` glibc heap,
while the controllable FrankenLibC strict-path overhead is now smaller.

## Non-comparable and infrastructure evidence

- A reverted-source baseline on `vmi1153651` produced different absolute timings
  and is recorded as routing evidence only, not keep/reject proof. It cannot be
  paired with the candidate because the candidate rerun was routed elsewhere and
  cancelled.
- A candidate rerun selected `ovh-a` despite worker preferences and was
  cancelled before completion because it was not a same-worker proof row.
- Worker `ovh-b` failed clean-target builds twice before project code with a
  `blake3 v1.8.5` build-script `SIGILL`; it was drained to avoid false negative
  proof runs.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-abi/src/malloc_abi.rs`:
  PASS.
- `rch exec -- cargo test -p frankenlibc-abi --test malloc_abi_test -- --nocapture`:
  PASS on `vmi1153651` (53 passed, 0 failed, 1 ignored).
- Earlier same-patch `rch exec -- cargo check -p frankenlibc-abi`: PASS with
  pre-existing warning debt.

## Retry predicate

Do not retry this exact slot-reuse shape; the easy redundant lookup is gone. The
remaining allocator losses are still not a one-branch or one-lock problem. Future
work should target a slimmer strict allocator fast path or a metadata layout that
reduces the amount of code touched per `calloc`/`free` cycle, and must be judged
with the same three-arm `fl`/`fl_native`/`glibc` benchmark.
