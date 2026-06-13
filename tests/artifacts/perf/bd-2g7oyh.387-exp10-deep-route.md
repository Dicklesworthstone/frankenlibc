# bd-2g7oyh.388 - exp10 deep range-reduction rejection

Date: 2026-06-13
Agent: BoldFalcon
Worker: vmi1153651
Verdict: REJECTED/restored, Score 0.0

Note: this artifact filename retains the pre-rebase local bead id
`bd-2g7oyh.387`; the tracker row was renumbered to `bd-2g7oyh.388` after
upstream concurrently used `.387` for a log2 keep.

## Target

Profile-backed target: `glibc_baseline_math/exp10`, selected after the kept
`bd-2g7oyh.386` log10f route. Broad RCH profile on `vmi1153651` at pushed
HEAD `2b3eddbc` left double `exp10` as a current p50-backed residual:
FrankenLibC p50/mean `769.000/800.459 ns` vs host `617.375/752.457 ns`.

Prior no-retry route: `bd-2g7oyh.382` already rejected the surface 1/16-centered
`exp10` table plus degree-12 Horner profile-band candidate.

## Focused Baseline

Command:

```text
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/exp10 --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

Same-worker focused baseline:

- FrankenLibC `exp10`: Criterion `[869.49 ns 933.01 ns 1.0166 us]`, p50/mean `824.295/938.748 ns`.
- Host glibc `exp10`: Criterion `[684.95 ns 746.26 ns 821.46 ns]`, p50/mean `650.092/733.603 ns`.

The focused gap reproduced materially: FrankenLibC was `1.27x` host by p50 and `1.28x` host by mean.

## Candidate Lever

One source lever tested:

- Add a bounded `exp2` profile-band helper for `p = x * log2(10)` where `x in [0.5, 2.5]`.
- Use a 1/64 fractional table for `2^(j/64)`, exponent-bit scaling, and a degree-7 Taylor residual over the centered remainder.
- Route `exp10` through that helper only when the profile-band gate accepts; preserve exact integer powers and the existing `libm::exp2(p)` fallback outside the gate.

Isomorphism contract:

- Floating point: preserve <=4 ULP envelope against `libm::exp10`/glibc; special cases and out-of-band fallbacks unchanged.
- Ordering/tie-breaking: no data-dependent ordering effects.
- RNG: not touched.
- Allocation/errno: not touched.

## Behavior Proof

Core proof:

```text
RCH_WORKER=vmi1153651 ... cargo test -j 1 -p frankenlibc-core --lib exp10 -- --nocapture --test-threads=1
```

Result: passed 7/7 exp10-related tests. Double `exp10` worst ULP stayed `4`.
Dense profile-band golden SHA:

```text
152b6bdcf3d70b30123b7ba0a54525b8578a1d0fb127fe027ec2f0962ca31b76
```

ABI/glibc replay:

```text
RCH_WORKER=vmi1153651 ... cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math diff_exp10_within_4_ulps -- --nocapture --test-threads=1
```

Result: passed 1/1.

## Post Benchmark

Same-worker post benchmark command matched the focused baseline command.

Post result:

- FrankenLibC `exp10`: Criterion `[1.3064 us 1.4203 us 1.5483 us]`, p50/mean `1194.236/1313.519 ns`.
- Host glibc `exp10`: Criterion `[676.19 ns 758.41 ns 862.03 ns]`, p50/mean `667.921/771.646 ns`.

Compared with focused baseline, the candidate regressed FrankenLibC `exp10` by
`44.9%` p50 and `39.9%` mean. Score is therefore `0.0`, despite passing behavior.

## Closeout

Source restored. Verification after restoration:

```text
git diff -- crates/frankenlibc-core/src/math/exp.rs crates/frankenlibc-core/src/math/float.rs
```

No diff.

Next route: do not retry 1/64 table/residual or surface `exp10` table/Horner
micro-variants. The next admissible primitive is an underlying generated,
proof-carrying `exp2` kernel replacement with coefficient synthesis and a
separate same-worker profile/proof gate.
