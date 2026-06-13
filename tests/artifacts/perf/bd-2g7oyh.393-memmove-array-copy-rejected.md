# bd-2g7oyh.393 memmove_4096 array-copy lowering gate

Date: 2026-06-13
Agent: BoldFalcon
Status: REJECTED-RESTORED

## Target

`bd-2g7oyh.391` kept `memmove_4096` in the routing table after a focused
same-worker RCH gate on `vmi1227854` showed a p50 gap, while prior no-ship
families ruled out another exact/general safe-SIMD copy panel or inline-only
hint.

This pass tested one materially different candidate: an exact `count == 4096`
safe-slice branch intended to make LLVM lower the hot path as a fixed-size copy.

## Current-Head Baseline

Head: `17e2a3255`

Command:

```text
RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd393-memmove-baseline-target-20260613T2211
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_memmove_4096 --noplot --sample-size 80 --warm-up-time 1
--measurement-time 4
```

RCH selected `vmi1227854`.

| impl | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | ---: | ---: | ---: | ---: |
| FrankenLibC | `[32.540 ns 32.983 ns 33.500 ns]` | 32.969 | 39.065 | 41.938 | 90.000 |
| host glibc | `[28.078 ns 28.442 ns 28.830 ns]` | 28.355 | 31.413 | 41.312 | 90.500 |

## Candidate

One source lever was tested in `crates/frankenlibc-core/src/string/mem.rs`:

- add `const MEMMOVE_EXACT_4096_BYTES: usize = 4096`;
- after the existing `count = min(n, dest.len(), src.len())`, branch when
  `count == 4096`;
- copy `dest[..4096].copy_from_slice(&src[..4096])`;
- return the unchanged `count`.

This preserves the same prefix length, destination suffix, byte order, and return
value as the existing implementation. FP, RNG, ordering, and tie-breaking do not
apply.

## Behavior Proof

RCH command:

```text
RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env
AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd393-memmove-proof-target-20260613T2217
cargo test -j 1 -p frankenlibc-core --lib
string::mem::tests::test_memmove_exact_4096_preserves_prefix_contract --
--nocapture
```

Result on `vmi1227854`: `1 passed; 0 failed; 3100 filtered out`.

Golden payload: deterministic destination bytes after the exact-4096 copy
(`src[i] = i*37+11 mod 256`, followed by seventeen `0xA5` suffix bytes).

Golden SHA-256:

```text
abaa13b6f9a5ccaa56e4f4b20d22a0421a0a780df1794353efb861ab66e548b4
```

## Codegen Proof

RCH command:

```text
RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env
AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 RUSTFLAGS=--emit=llvm-ir
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd393-memmove-ir-target-20260613T2220
cargo build -j 1 -p frankenlibc-core --release
```

The generated IR did **not** preserve the intended fixed-size copy. Optimized
`frankenlibc_core::string::mem::memmove` still lowers to a single dynamic-length
copy:

```text
define ... frankenlibc_core::string::mem::memmove(...)
  %_0.sroa.0.0.i = tail call noundef i64 @llvm.umin.i64(i64 %dest.1, i64 %n)
  %_0.sroa.0.0.i1 = tail call noundef i64 @llvm.umin.i64(i64 %src.1, i64 %_0.sroa.0.0.i)
  tail call void @llvm.memcpy.p0.p0.i64(ptr ... %dest.0, ptr ... %src.0, i64 %_0.sroa.0.0.i1, i1 false)
  ret i64 %_0.sroa.0.0.i1
```

No retained `i64 4096` memcpy was present in the `memmove` function body.

## Same-Worker Post

Command:

```text
RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd393-memmove-post-target-20260613T2223
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_memmove_4096 --noplot --sample-size 80 --warm-up-time 1
--measurement-time 4
```

RCH selected `vmi1227854`.

| impl | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | ---: | ---: | ---: | ---: |
| FrankenLibC | `[31.823 ns 32.238 ns 32.695 ns]` | 31.901 | 35.401 | 36.394 | 45.500 |
| host glibc | `[27.536 ns 27.883 ns 28.251 ns]` | 28.259 | 30.289 | 35.062 | 70.000 |

The post numbers showed an apparent p50/mean improvement, but the optimized IR
proved the candidate did not change the generated `memmove` primitive. The
apparent gain is therefore not enough to ship under the one-lever/codegen-proof
gate.

## Verdict

REJECTED-RESTORED. Score `0.0`.

The source hunk was removed; `git diff -- crates/frankenlibc-core/src/string/mem.rs`
is empty.

Next route: do not retry surface exact-size safe-slice branches for `memmove`.
The next admissible primitive must change codegen or representation materially,
for example an ABI-level no-overlap raw-pointer classification lane with a
separate proof that the safe core contract is preserved, or a generated
disassembly-backed copy primitive that demonstrably emits a different lowering.
