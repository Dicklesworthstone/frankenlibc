# bd-2g7oyh.440 printf_g_6 focused no-code gate

Date: 2026-06-16
Agent: BoldFalcon
Worker: vmi1227854
Commit under test: 1fabf6f8c4c84bf04d06b3d6c164ea61ab563b1b

## Route

Pass 156 broad RCH routing on `vmi1227854` showed
`glibc_baseline_printf_float/printf_g_6` as a possible residual:

- FrankenLibC p50/mean: 154.628 / 159.964 ns
- host glibc p50/mean: 129.916 / 131.583 ns

That broad row was routing evidence only. Prior `%g` artifacts
(`bd-2g7oyh.318`, `bd-2g7oyh.336`, `bd-2g7oyh.418`) showed that broad or
cross-worker `printf_g_6` rows can collapse or reverse under focused gates.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=2400 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass158-printfg-target-baseline \
CRITERION_HOME=/data/tmp/frankenlibc-pass158-printfg-criterion-baseline \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
printf_g_6 --noplot --sample-size 70 --warm-up-time 0.7 --measurement-time 3
```

Focused result on `vmi1227854`:

- FrankenLibC Criterion interval: [137.36 ns 141.54 ns 145.97 ns]
- FrankenLibC p50/mean: 147.233 / 152.113 ns
- host glibc Criterion interval: [144.36 ns 148.43 ns 152.55 ns]
- host glibc p50/mean: 153.660 / 156.494 ns

Captured RCH log SHA256:

```text
513f6a8f735de03601403155a02ed852ed6b70a751b19f7f61f4d1346e27d4a0  /data/tmp/frankenlibc-pass158-printfg-baseline-vmi1149989.log
```

The filename reflects the first planned worker; RCH selected `vmi1227854`.

## Verdict

NO-CODE REJECTED. The focused gate does not reproduce a vs-host gap.
FrankenLibC is faster than host on both p50 and mean:

- p50: 147.233 ns vs 153.660 ns
- mean: 152.113 ns vs 156.494 ns

Score: 0.0. No implementation source changed.

## Behavior Proof

Behavior is unchanged by construction:

- Ordering/tie-breaking: unchanged; no formatting path changed.
- Floating-point output: unchanged; `format_float`, `format_g`, and helpers are
  untouched.
- RNG/allocation behavior: unchanged; no code changed.
- Golden output: existing printf differential/golden tests remain applicable.

Source SHA256 for the unchanged implementation:

```text
50a8f132a6f8334c38f3ad3da67304e0df54ddfb99439fa08f4b5741c1701614  crates/frankenlibc-core/src/stdio/printf.rs
```

## Reroute

Do not optimize `printf_g_6` from this broad row. Reprofile current head and
select a target whose focused same-worker p50 and mean both reproduce a material
gap, or continue to the next unowned residual from the current route table with a
fresh focused gate.
