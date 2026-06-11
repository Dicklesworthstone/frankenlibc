# bd-2g7oyh.337 cbrt focused gate

Date: 2026-06-11

## Target

`bd-2g7oyh.337` targeted `glibc_baseline_math/cbrt` after a broad RCH
profile showed an apparent residual for `cbrt(x) x in [0.5,2.5)`.

Broad routing evidence from RCH `ovh-a` job `29879662679166241`:

- FrankenLibC: p50 `1243.727 ns/op`, mean `1240.301 ns/op`
- host glibc: p50 `932.375 ns/op`, mean `955.890 ns/op`

This broad row was treated as routing evidence only. No source edit was allowed
unless a focused same-worker gate reproduced a material gap.

## Focused RCH Gate

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=CodexOpt FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass65-cbrt-focused-baseline \
  cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_math/cbrt \
  --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH worker/job:

- worker: `vmi1227854`
- job: `29879662679166306`

Focused result:

- FrankenLibC: p50 `917.952 ns/op`, mean `930.829 ns/op`, p95 `1244.773 ns/op`, p99 `1261.046 ns/op`
- host glibc: p50 `1113.618 ns/op`, mean `1041.923 ns/op`, p95 `1199.813 ns/op`, p99 `1314.516 ns/op`

## Verdict

No-code rejected, Score `0.0`.

The focused same-worker gate reversed the broad row. FrankenLibC was faster than
host glibc by p50 and mean, so editing `cbrt` would violate the profile-backed
target rule.

## Behavior Proof

No source was edited.

Source hashes:

- `crates/frankenlibc-core/src/math/float.rs`: `bbb9f858c6e858391455b471ef06c3fcd23d894ea055e72d0cc7bd8c498ec978`
- `crates/frankenlibc-abi/src/math_abi.rs`: `d305aa7749d912ce496ef256010a11715c87c86cae80e8368a1a9d0de1a551de`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`
- `crates/frankenlibc-core/tests/math_special_differential_probe.rs`: `fa4cf3ee38589b2ba33cf9f67623df0dcdcaa984790f59b5fc64cdaaf4df4188`

Isomorphism:

- ordering/tie-breaking: unchanged by construction
- floating-point: unchanged by construction; `cbrt` remains the existing `libm::cbrt` path
- RNG: not used
- golden output: existing cbrt differential/special-case coverage remains unchanged; no new generated output was introduced

## Next Route

Continue with a different profile-backed unowned residual after a focused RCH
gate. Do not replace `cbrt` without a renewed material same-worker gap and an
interval-certified/minimax artifact with special-value and 4-ULP glibc replay.
