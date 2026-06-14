# bd-2g7oyh.396 memcmp_4096 codegen gate

Date: 2026-06-14
Agent: BoldFalcon
Status: NO-CODE REJECTED

## ID note

`bd-2g7oyh.396` was created for this memcmp pass after the repository already
contained the tracked artifact `bd-2g7oyh.396-memcpy-4096-focused.md` from a
separate no-code memcpy route. This artifact keeps the bead id and uses a
distinct suffix.

## Target

Fresh focused RCH gate on current `HEAD` (`7f1fdb0ed`) reproduced a material
`memcmp_4096` equal-buffer gap on `vmi1227854`.

```text
RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd398-memcmp4096-baseline-target-20260614Tfocus
CRITERION_HOME=/data/tmp/frankenlibc-bd398-memcmp4096-baseline-criterion-20260614Tfocus
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_memcmp_4096 --noplot --sample-size 60 --warm-up-time 1
--measurement-time 3
```

RCH selected `vmi1227854`.

| implementation | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[49.939 ns 50.330 ns 50.773 ns]` | 51.049 | 53.745 | 56.317 | 90.000 |
| host glibc | `[37.461 ns 38.149 ns 38.795 ns]` | 37.247 | 39.734 | 41.922 | 80.000 |

The focused gap is `1.37x` by p50 and `1.35x` by mean.

## Prior no-ship families

Do not repeat these without a materially different generated-code primitive:

- folded-panel widening and exact-size superfolds;
- exact 4096 certificates;
- 64-lane rank/select;
- broadword extraction;
- cross-crate inline;
- chunk-cursor retuning;
- XOR/test-zero folded predicate retuning.

## Codegen diagnostic

A crate-scoped assembly diagnostic was built with:

```text
AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd396-memcmp-asm-target-20260614
cargo rustc -j 1 -p frankenlibc-core --lib --profile bench -- --emit=asm
```

This diagnostic did not print the RCH banner, so it is used only as local
source-codegen routing evidence, not as keep/reject benchmark proof.

The current `frankenlibc_core::string::mem::memcmp` body shows the hot
equal-block loop lowering the 128-byte certificate to compare-mask work:

```text
vmovdqu ...
vpcmpeqb ...
vpand ...
vpmovmskb ...
cmpl $-1, ...
```

Even though the Rust helper is written as XOR/OR over four 32-byte vectors, LLVM
selects the compare-mask form for the hot equal loop. The obvious source-level
response would be another XOR/test-zero or reduction retune, but that family is
already rejected in `bd-4ycflz-memcmp-xor-fold-rejection.md`.

## Isomorphism

No source code changed.

- Ordering and first-difference tie-breaking are unchanged by construction.
- Floating-point and RNG are not involved.
- Golden output and fixture hashes are unchanged by construction.

## Verdict

NO-CODE REJECTED. Score `0.0`.

The focused gap is real, but the only immediate in-source edit suggested by the
assembly diagnostic repeats a documented rejected family. The next memcmp pass
needs a fundamentally different generated-code primitive, such as a proof-backed
load/test lowering artifact that demonstrably changes the emitted hot loop
before source changes, or the campaign should route to a different reproduced
primitive.

Next route: profile/focus the allocator lane for a deeper segregated slab or
intrusive hot-list primitive rather than continue memcmp folded-loop tuning.
