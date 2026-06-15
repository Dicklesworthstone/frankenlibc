# bd-2g7oyh.409 memchr_absent generated-code route no-code closeout

## Target

- Bead: `bd-2g7oyh.409`
- Parent: `bd-2g7oyh`
- Re-key reason: remote `bd-2g7oyh.408` exp10 closeout landed before the memchr closeout push.
- Routing source: Pass 110 broad RCH slice on `ovh-a`
- Profile-backed routing row: `glibc_baseline_memchr_absent`
- Workload: 4096-byte scan for an absent byte
- Focused baseline source: `d2e03d723`; current `origin/main` `3e5e3f7f0` changed only bead/progress/artifact metadata, not source.
- RCH worker: `ovh-a`

## Routing Evidence

The broad current-head routing slice selected `memchr_absent` as the largest apparent residual:

```text
GLIBC_BASELINE_BENCH profile_id=memchr_absent impl=frankenlibc_core p50_ns_op=40.579 mean_ns_op=37.130
GLIBC_BASELINE_BENCH profile_id=memchr_absent impl=host_glibc p50_ns_op=18.797 mean_ns_op=20.953
```

Prior no-retry families from the tracker/memory screen:

- panel-width changes
- wider folded blocks
- indexed folded scans
- SWAR word-group scans
- resolver retuning

The only admissible source route would have been a materially different generated/codegen-backed primitive with assembly/IR evidence.

## Focused Same-Worker Baseline

Required focused baseline before source edits:

```text
glibc_baseline_memchr_absent/memchr_absent/frankenlibc_core
                        time:   [19.717 ns 19.769 ns 19.839 ns]
GLIBC_BASELINE_BENCH profile_id=memchr_absent impl=frankenlibc_core api_family=string symbol=memchr workload="4096-byte scan for absent byte" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=86 p50_ns_op=19.796 p95_ns_op=22.500 p99_ns_op=40.000 mean_ns_op=21.117 throughput_ops_s=49984106.369 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=crates/frankenlibc-core/src/string/mem.rs

glibc_baseline_memchr_absent/memchr_absent/host_glibc
                        time:   [18.267 ns 18.299 ns 18.331 ns]
GLIBC_BASELINE_BENCH profile_id=memchr_absent impl=host_glibc api_family=string symbol=memchr workload="4096-byte scan for absent byte" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=86 p50_ns_op=18.346 p95_ns_op=37.562 p99_ns_op=50.000 mean_ns_op=22.661 throughput_ops_s=54381257.270 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=crates/frankenlibc-core/src/string/mem.rs
```

Focused baseline command:

```bash
RCH_BUILD_SLOTS=1 RCH_WORKERS=ovh-a RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd408-memchr-baseline-target-20260615T0027 CRITERION_HOME=/data/tmp/frankenlibc-bd408-memchr-baseline-criterion-20260615T0027 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_memchr_absent' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

## Verdict

NO-CODE REJECTED, Score `0.0`.

The focused gate reduced the p50 gap to `1.08x` (`1.450 ns`) and flipped mean in FrankenLibC's favor (`21.117 ns` vs host `22.661 ns`). A source edit would not be profile-backed enough for the no-gaps keep gate, and the known `memchr_absent` microfamilies remain off-limits.

Behavior is unchanged by construction:

- first-match ordering and absent-result semantics unchanged
- pointer/null/length behavior unchanged
- golden outputs unchanged
- FP/RNG/allocation not involved

Next route: reprofile or focus another residual from the routing slice. Do not retry `memchr_absent` without a fresh same-worker material gap and a genuinely different generated/codegen-backed primitive.
