# bd-2g7oyh.334 exp10 focused gate

## Target

`bd-2g7oyh.334` targeted `glibc_baseline_math/exp10` after pass-60 broad
profiling on `vmi1227854` showed a renewed apparent f64 residual:

- FrankenLibC p50 `396.778 ns`, mean `416.767 ns`
- host glibc p50 `349.405 ns`, mean `362.812 ns`

Prior artifact `bd-3kqk9k-exp10-focused-gate.md` had already rejected a
focused f64 `exp10` miss at p50 parity, so this pass was a fresh focused gate
only. A source edit would require a generated table/minimax artifact, not a
retune of the existing compensated `exp2(x * log2(10))` reduction.

## Focused RCH Baseline

Initial attempt:

```text
RCH local (no admissible workers: critical_pressure=1,insufficient_slots=1)
RCH remote required; refusing local fallback
```

After a short wait, the remote-only retry succeeded.

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKERS=vmi1227854 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass62-exp10-baseline \
rch exec -- cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_math/exp10
```

Worker and result:

- RCH worker: `vmi1227854`
- RCH job: `29879662679165936`
- RCH result: exit `0`, remote summary `221.7s`

Target f64 `exp10` output:

- FrankenLibC: p50 `324.206 ns`, p95 `466.000 ns`, p99 `892.000 ns`,
  mean `347.453 ns`, throughput `3132033.483 ops/s`
- host glibc: p50 `349.241 ns`, p95 `397.470 ns`, p99 `561.000 ns`,
  mean `358.621 ns`, throughput `2860148.657 ops/s`

The filter also matched non-target `exp10f`:

- FrankenLibC: p50 `342.547 ns`, mean `355.181 ns`
- host glibc: p50 `334.180 ns`, mean `347.709 ns`

That f32 row was too small and was not this bead's target.

## Proof

No source edit was made. Behavior is unchanged by construction:

- `crates/frankenlibc-core/src/math/float.rs` sha256:
  `bbb9f858c6e858391455b471ef06c3fcd23d894ea055e72d0cc7bd8c498ec978`
- `crates/frankenlibc-core/src/math/float32.rs` sha256:
  `78ac9d96f0ad7b98c93f7d52772153402405ab85739f0a7093dbe8f65872b764`
- `crates/frankenlibc-abi/src/math_abi.rs` sha256:
  `d305aa7749d912ce496ef256010a11715c87c86cae80e8368a1a9d0de1a551de`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs` sha256:
  `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`
- `git diff --exit-code -- crates/frankenlibc-core/src/math/float.rs crates/frankenlibc-core/src/math/float32.rs crates/frankenlibc-abi/src/math_abi.rs crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`
  passed.
- Exact integer semantics, range fallback ordering, finite/special
  floating-point behavior, errno handling, ABI forwarding, fixture outputs, and
  RNG behavior were not touched.

## Verdict

NO-CODE REJECTED, Score `0.0`.

The focused f64 `exp10` gate did not reproduce the broad gap. FrankenLibC was
faster than host glibc by both p50 and mean, so a source edit would violate the
profile-backed target rule.

Next route: pick a different reproduced unowned residual. Do not revisit f64
`exp10` without a material focused same-worker gap and a generated
table/minimax artifact.
