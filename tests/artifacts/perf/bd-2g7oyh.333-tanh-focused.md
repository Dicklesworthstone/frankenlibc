# bd-2g7oyh.333 tanh focused gate

## Target

`bd-2g7oyh.333` targeted `glibc_baseline_math/tanh` after a broad RCH
profile on `vmi1227854` showed an apparent unowned residual:

- FrankenLibC p50 `733.171 ns`, mean `736.549 ns`
- host glibc p50 `606.168 ns`, mean `607.717 ns`

The replacement bead ID was needed because a peer landed `bd-2g7oyh.332` for a
memmove closeout while this focused tanh gate was being recorded.

## Focused RCH Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKERS=vmi1227854 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass60-tanh-baseline \
rch exec -- cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_math/tanh
```

Worker and result:

- RCH worker: `vmi1227854`
- RCH job: `29879662679165917`
- RCH result: exit `0`, remote summary `219.0s`

Criterion interval output:

- FrankenLibC: `[779.07 ns 816.76 ns 835.34 ns]`
- host glibc: `[636.81 ns 683.33 ns 768.17 ns]`

`GLIBC_BASELINE_BENCH` sampled output:

- FrankenLibC: p50 `751.208 ns`, p95 `847.637 ns`, p99 `848.227 ns`,
  mean `744.034 ns`, throughput `1270552.611 ops/s`
- host glibc: p50 `937.500 ns`, p95 `1181.000 ns`, p99 `1208.688 ns`,
  mean `880.224 ns`, throughput `1360615.682 ops/s`

## Proof

No source edit was made. Behavior is unchanged by construction:

- `crates/frankenlibc-core/src/math/trig.rs` sha256:
  `d0d5ad79945010878a18b01a364a7730821a4e5567605eeca82bb1cac3fd827c`
- `crates/frankenlibc-abi/src/math_abi.rs` sha256:
  `d305aa7749d912ce496ef256010a11715c87c86cae80e8368a1a9d0de1a551de`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs` sha256:
  `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`
- `git diff --exit-code -- crates/frankenlibc-core/src/math/trig.rs crates/frankenlibc-abi/src/math_abi.rs crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`
  passed.
- Finite/special floating-point behavior, odd symmetry, saturation behavior,
  errno handling, ABI forwarding, fixture outputs, and RNG behavior were not
  touched.

## Verdict

NO-CODE REJECTED, Score `0.0`.

The focused same-worker gate reversed the broad result. FrankenLibC was faster
than host glibc by both p50 and mean, so a `tanh` source edit would violate the
profile-backed target rule.

Next route: continue from the broad table with a different reproduced unowned
residual, likely `exp10` before `lgamma`, unless new ready perf beads appear.
