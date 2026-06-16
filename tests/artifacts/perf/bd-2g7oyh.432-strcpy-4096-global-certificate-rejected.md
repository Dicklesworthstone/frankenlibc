# bd-2g7oyh.432 - strcpy_4096 global NUL-certificate rejection

Date: 2026-06-16
Agent: BoldFalcon
Worker: `vmi1227854`
Status: rejected, source restored

## Target

Profile-backed row: `glibc_baseline_strcpy_4096`

Focused same-worker baseline:

- Command: `cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3`
- FrankenLibC Criterion: `[60.000 ns 60.457 ns 60.890 ns]`
- FrankenLibC profile line: p50 `59.711 ns`, mean `61.237 ns`
- host glibc Criterion: `[39.665 ns 40.577 ns 41.406 ns]`
- host glibc profile line: p50 `40.780 ns`, mean `41.586 ns`

## Candidate

One lever tested:

- Add a single 4096-byte payload NUL certificate for `strcpy_4096_terminated`.
- Fold every 64-byte SIMD panel through a min accumulator.
- If no zero exists in the payload, bulk-copy the known 4097-byte `4096 + NUL` terminal-boundary slice.
- Preserve all early-NUL paths by falling back to the existing ordered 512-byte resolver.

This was a deeper generated/global certificate shape, not another terminal split or wrapper-inline retry.

## Behavior proof

RCH command:

```text
cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1
```

Result:

- 7/7 filtered tests passed.
- `test_strcpy_golden_transcript_sha256` passed with SHA `fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401`.
- Exact 4096 early-NUL tail preservation passed.
- No-NUL panic contract passed.
- First-NUL ordering, copied byte count, destination tail behavior, FP, RNG, allocation, errno, and locale behavior are unchanged.

## Post benchmark

RCH command:

```text
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Candidate result:

- FrankenLibC Criterion: `[69.503 ns 71.823 ns 74.780 ns]`
- FrankenLibC profile line: p50 `67.875 ns`, mean `77.177 ns`
- host glibc Criterion: `[39.122 ns 39.916 ns 40.760 ns]`
- host glibc profile line: p50 `42.026 ns`, mean `43.183 ns`

Same-worker self delta:

- p50: `59.711 -> 67.875 ns`, `13.7%` slower.
- mean: `61.237 -> 77.177 ns`, `26.0%` slower.
- Criterion center: `60.457 -> 71.823 ns`, `18.8%` slower.

## Verdict

Rejected and restored. Score: `0.0`.

Do not retry global NUL certificates, terminal-NUL splitting, dispatch hoists, array-copy lowering, scalar terminal splitting, or public-wrapper inlining for `strcpy_4096`. Return only with a generated/backend-dispatch or ABI-level terminal/no-overlap primitive after a fresh focused gate.
