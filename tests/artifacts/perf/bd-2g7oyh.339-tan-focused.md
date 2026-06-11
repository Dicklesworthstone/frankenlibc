# bd-2g7oyh.339 tan focused math gate

Date: 2026-06-11

## Target

`bd-2g7oyh.339` targeted `glibc_baseline_math/tan`, `tan(x)` for
`x in [0.5,2.5)`.

Broad routing evidence from RCH `ovh-a` job `29879662679166241`:

- FrankenLibC: p50 `940.410 ns/op`, mean `1039.430 ns/op`
- host glibc: p50 `668.281 ns/op`, mean `741.323 ns/op`

## Focused RCH Gate

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=CodexOpt FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass67-tan-focused-baseline \
  cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_math/tan \
  --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH worker/job:

- worker: `vmi1227854`
- job: `29879662679166333`

The Criterion filter also matched non-target `tanh` and `tanhf` rows. The
decision below uses only rows with `profile_id=tan`.

Focused target result:

- FrankenLibC `tan`: p50 `651.439 ns/op`, mean `686.921 ns/op`, p95 `732.901 ns/op`, p99 `876.500 ns/op`
- host glibc `tan`: p50 `774.477 ns/op`, mean `782.580 ns/op`, p95 `831.204 ns/op`, p99 `982.531 ns/op`

## Verdict

No-code rejected, Score `0.0`.

The focused same-worker target row reversed the broad result. FrankenLibC was
faster than host glibc by p50 and mean, so replacing `tan` would violate the
profile-backed target rule.

## Behavior Proof

No source was edited.

Source hashes:

- `crates/frankenlibc-core/src/math/trig.rs`: `d0d5ad79945010878a18b01a364a7730821a4e5567605eeca82bb1cac3fd827c`
- `crates/frankenlibc-abi/src/math_abi.rs`: `d305aa7749d912ce496ef256010a11715c87c86cae80e8368a1a9d0de1a551de`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`
- `crates/frankenlibc-core/tests/math_special_differential_probe.rs`: `fa4cf3ee38589b2ba33cf9f67623df0dcdcaa984790f59b5fc64cdaaf4df4188`

Isomorphism:

- ordering/tie-breaking: unchanged by construction
- floating-point: unchanged by construction; `tan` remains the existing `libm::tan` path
- RNG: not used
- golden output: existing math differential coverage remains unchanged; no new generated output was introduced

## Next Route

Continue with a different profile-backed unowned residual. Do not revisit `tan`
without a renewed material same-worker gap and an interval-certified
range-reduction/minimax artifact with special-value and 4-ULP glibc replay.
