# `bd-alkove.1` group fingerprint raw-syscall reject

Date: 2026-07-14
Agent: BlackThrush / cod
Base commit: `0840a3d15fce5b328fd93ee1a59a82c0937a6304`

## Target and attribution

`bv --robot-triage` plus the negative-evidence rehabilitation queue led to
`bd-alkove` L6713. The old default-`/etc/group` stat skip was not retried: it
can miss a live file update. Instead, this candidate preserved the per-call
fingerprint check and replaced only `GrpStorage::file_fingerprint_cstr`'s call
through the public `stat` ABI with the same `newfstatat` syscall used by that
ABI. The hypothesis was that nested runtime-policy work dominated the hot
fingerprint probe.

The same release binary timed:

- the legacy public `stat` entry;
- direct `sys_newfstatat`;
- a second identical direct-syscall arm as the null control; and
- deployed `getgrgid(0)` as an end-to-end guard.

Before timing, assertions required exact `(st_size, st_mtime,
st_mtime_nsec)` equality for `/etc/group` and identical failure
classification for a missing path. Both passed.

## One foreground remote release gate

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1153651 RCH_WORKERS=vmi1153651 \
RCH_PREFERRED_WORKER=vmi1153651 RCH_QUEUE_WHEN_BUSY=1 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,FRANKENLIBC_BENCH_PIN,CARGO_BUILD_JOBS \
rch exec -- env AGENT_NAME=BlackThrush CARGO_BUILD_JOBS=1 \
FRANKENLIBC_BENCH_PIN=1 \
CARGO_TARGET_DIR=/data/projects/frankenlibc/.rch-target-vmi1153651-pool-2e4cba3fadfae9af98dac7851bc7fbe6 \
CRITERION_HOME=/data/projects/frankenlibc/.rch-target-vmi1153651-pool-2e4cba3fadfae9af98dac7851bc7fbe6/criterion-bd-alkove-1 \
cargo bench -j 1 -p frankenlibc-bench --profile release --features abi-bench \
--bench glibc_baseline_bench -- glibc_baseline_grp_stat_probe_ab \
--noplot --sample-size 15 --warm-up-time 0.05 --measurement-time 0.15
```

- Actual worker: `vmi1153651`.
- Profile: ordinary `release`; `release-perf` was never used.
- RCH remapped the requested target to worker pool
  `52cb8389992c89401e7474ec3f19ef5a` and rebuilt it; build time was 9m03s.
- RCH did not retrieve the executable itself, so a binary SHA-256 is
  unavailable. The worker, base commit, exact command, pool identity, and raw
  Criterion output are recorded here instead.

| arm | custom p50 ns/op | custom mean ns/op | Criterion interval |
|---|---:|---:|---:|
| legacy public `stat` | 1149.296 | 1654.008 | 1190.3-2840.9 ns |
| raw `newfstatat` candidate | 1287.188 | 1903.546 | 1371.7-2448.0 ns |
| raw `newfstatat` null | 1198.350 | 1342.606 | 1228.3-1407.9 ns |
| deployed `getgrgid(0)` guard | 2454.018 | 3092.198 | 2312.8-2641.7 ns |

Ratios by custom p50:

- candidate / legacy = **1.120x** (12.0% slower);
- candidate / identical-candidate null = **1.074x**;
- legacy / identical-candidate null = **0.959x**.

## Verdict

**REJECTED and reverted.** The candidate did not beat the incumbent, and the
sequential identical-arm null itself moved 7.4%, so there is no positive effect
outside the measured floor. Both the production edit and the temporary
benchmark instrumentation were removed. This closes only the direct-raw-stat
retry; `bd-alkove`'s separate passwd-parser rehabilitation remains open.

No second benchmark and no local Cargo command ran. The remote build completed
with existing unrelated warnings in core/ABI code and the existing missing-SMT
solver notice; neither came from this reverted candidate.
