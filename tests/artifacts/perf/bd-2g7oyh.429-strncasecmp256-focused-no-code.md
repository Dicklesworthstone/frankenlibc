# bd-2g7oyh.429 - strncasecmp_256_equal Focused Gate No-Code

Date: 2026-06-16T04:30Z
Agent: BoldFalcon
Worker: vmi1227854
Target: `glibc_baseline_strncasecmp_256_equal`
Verdict: NO-CODE ROUTED OUT
Score: 0.0

## Profile-Backed Target

Pass 144 broad routing profile on `vmi1227854` suggested a current-head
`strncasecmp_256_equal` residual:

- FrankenLibC Criterion: `[11.128 ns 11.356 ns 11.573 ns]`
- FrankenLibC p50/mean: `11.365/12.802 ns`
- Host glibc Criterion: `[7.4231 ns 7.8770 ns 8.3243 ns]`
- Host glibc p50/mean: `8.055/9.516 ns`

Prior no-retry families for this lane:

- exact-256 folded-equality certificates
- SIMD lane-count reshaping

The next admissible source route would have been a genuinely different
branchless byte-transducer or generated-code primitive, but only after a
focused same-worker baseline reproduced the gap.

## Focused RCH Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary \
RCH_BUILD_SLOTS=1 \
RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env \
  AGENT_NAME=BoldFalcon \
  FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass146-strncasecmp256-baseline-target-20260616T0430 \
  CRITERION_HOME=/data/tmp/frankenlibc-pass146-strncasecmp256-baseline-criterion-20260616T0430 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
    glibc_baseline_strncasecmp_256_equal \
    --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Result:

```text
glibc_baseline_strncasecmp_256_equal/strncasecmp_256_equal/frankenlibc_core
time: [10.953 ns 11.098 ns 11.251 ns]
GLIBC_BASELINE_BENCH ... p50_ns_op=11.280 p95_ns_op=15.627 p99_ns_op=60.000 mean_ns_op=12.539

glibc_baseline_strncasecmp_256_equal/strncasecmp_256_equal/host_glibc
time: [11.417 ns 11.721 ns 12.041 ns]
GLIBC_BASELINE_BENCH ... p50_ns_op=12.324 p95_ns_op=15.000 p99_ns_op=50.000 mean_ns_op=13.644

[RCH] remote vmi1227854
```

## Behavior Proof

No source edit was made. Behavior is unchanged by identity:

- Ordering and tie-breaking: unchanged; existing `strncasecmp` implementation remains in place.
- Floating point: not involved.
- RNG: not involved.
- Golden-output SHA: no output-producing code path changed; existing committed string
  golden artifacts remain authoritative.

## Decision

The focused same-worker gate did not reproduce a deficit. FrankenLibC was faster
than host glibc on Criterion center, p50, and mean:

- Criterion center: `11.098 ns` vs host `11.721 ns`
- p50: `11.280 ns` vs host `12.324 ns`
- mean: `12.539 ns` vs host `13.644 ns`

No code lever is profile-backed here. The bead is closed no-code and the next
step is a fresh current-head reprofile because bottleneck ordering shifted under
the rebased remote head.
