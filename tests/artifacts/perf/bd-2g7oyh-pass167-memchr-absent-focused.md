# bd-2g7oyh.449 memchr_absent focused no-code closeout

Pass: 167
Agent: BoldFalcon
Date: 2026-06-17
Target: `glibc_baseline_memchr_absent`
Mode: local cargo/Criterion because `ts1`/remote RCH is offline

## Baseline Command

```bash
env AGENT_NAME=BoldFalcon \
  RCH_REQUIRE_REMOTE=0 \
  FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass167-memchr-baseline-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass167-memchr-baseline-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memchr_absent \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Log:

```text
/data/tmp/frankenlibc-pass167-memchr-baseline.log
sha256 6ed6743514f887092b97d166ee30575c9743621d5c7329263f105f19fd31b943
```

The run initially waited on a Cargo lock held by another local `frankenlibc-abi`
clippy/check path, then completed after the lock cleared. No concurrent
FrankenLibC cargo command was started by this pass.

## Focused Results

| impl | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[23.983, 24.574, 25.129] ns` | `23.268` | `24.883` | `28.069` | `35.000` |
| host glibc | `[19.837, 20.281, 20.799] ns` | `19.660` | `27.233` | `23.786` | `60.500` |

The focused run preserves a p50/center residual but reverses on mean. Since the
recent `memchr_absent` history already rejected folded-panel widening,
exact-4096 dispatch, `contains` certificates, loop/tail rearrangement, SWAR
word-group scans, rank/select, indexed folded scans, wrapper inlining, and hot
or cold outlining, this evidence does not justify another source lever.

## Behavior Proof

No implementation source changed.

```bash
git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs
```

passed.

Identity proof:

- First-match ordering and tie-breaking are unchanged.
- Absent result stays `None`.
- The `n` clamp and no-read-past-slice behavior are unchanged.
- Existing wide-character sibling behavior is untouched.
- FP, RNG, allocation, errno, and locale state are untouched.
- Existing golden memchr outputs remain governed by the unchanged tests.

## Verdict

NO-CODE ROUTED OUT. Score `0.0`.

Close `bd-2g7oyh.449` with this evidence and reprofile current head before
selecting the next residual. Do not return to `memchr_absent` without a fresh
material focused gap on both p50 and mean and a genuinely different
generated/backend-dispatch primitive.
