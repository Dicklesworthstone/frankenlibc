# bd-2g7oyh.340 strpbrk_absent focused gate

Date: 2026-06-11

## Target

`bd-2g7oyh.340` targeted `glibc_baseline_strpbrk_absent`, a 4096-byte
NUL-terminated scan with an 8-byte accept set absent from the haystack.

Broad routing evidence from RCH `vmi1153651` job `29883510449766560`:

- FrankenLibC: p50 `405.500 ns/op`, mean `494.261 ns/op`
- host glibc: p50 `343.458 ns/op`, mean `404.201 ns/op`

## Focused RCH Gate

Command:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 \
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd340-strpbrk-focused-baseline \
  cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_strpbrk_absent \
  --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH worker/job:

- worker: `vmi1153651`
- job: `29883510449766609`

Focused result:

- FrankenLibC: p50 `421.545 ns/op`, mean `531.137 ns/op`, p95 `667.179 ns/op`, p99 `1047.617 ns/op`
- host glibc: p50 `426.826 ns/op`, mean `932.444 ns/op`, p95 `2402.711 ns/op`, p99 `7404.851 ns/op`

## Verdict

No-code rejected, Score `0.0`.

The focused same-worker gate reversed the broad row. FrankenLibC was slightly
faster by p50 and materially faster by mean on the target row, while the host
row carried severe high outliers. A `strpbrk` source edit would violate the
profile-backed target rule.

The next admissible `strpbrk` attack remains a fundamentally different sparse
accept-set classifier or generated codegen/disassembly artifact, not another
small in-source branch. It should only be attempted after a fresh focused gate
reproduces a material same-worker residual.

## Behavior Proof

No source was edited.

Source hashes:

- `crates/frankenlibc-core/src/string/str.rs`: `5eb2974530ce7264233c9788e0ded187cd318aeb794ebaf88a4d94ef7fbbe8ef`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`

Isomorphism:

- ordering/tie-breaking: unchanged by construction; first haystack byte with membership in the accept set remains the existing implementation contract
- floating-point: N/A
- RNG: not used
- golden output: existing `strpbrk` behavior remains unchanged; no new generated output was introduced

## Next Route

Continue with a different profile-backed unowned residual. Do not revisit
`strpbrk_absent` without a renewed material same-worker gap and a sparse
accept-set or codegen-backed primitive with golden-output replay.
