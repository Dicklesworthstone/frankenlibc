# bd-2g7oyh.338 memcmp_4096 focused non-retry gate

Date: 2026-06-11

## Target

`bd-2g7oyh.338` targeted `glibc_baseline_memcmp_4096`, equal 4096-byte
buffers.

Broad routing evidence from RCH `ovh-a` job `29879662679166241`:

- FrankenLibC: p50 `72.641 ns/op`, mean `68.740 ns/op`
- host glibc: p50 `42.002 ns/op`, mean `45.494 ns/op`

## Focused RCH Gate

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=CodexOpt FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass66-memcmp4096-focused-baseline \
  cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_memcmp_4096 \
  --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH worker/job:

- worker: `vmi1227854`
- job: `29879662679166319`

Focused result:

- FrankenLibC: p50 `50.421 ns/op`, mean `65.823 ns/op`, p95 `79.942 ns/op`, p99 `315.484 ns/op`
- host glibc: p50 `42.736 ns/op`, mean `45.351 ns/op`, p95 `55.761 ns/op`, p99 `75.500 ns/op`

## Verdict

No-code rejected, Score `0.0`.

The focused gate reproduced a real residual, but the in-source safe-Rust lever
space available here repeats prior rejected families. Current `memcmp` already
uses portable-SIMD folded equality panels. Prior rejected `memcmp_4096` families
include exact-4096 superfold, 512-byte folded blocks, folded-panel widening,
broadword extraction, rank/select, cross-crate inline, and exact/certificate
widening. Another local widening branch would be the wrong primitive.

The next admissible `memcmp` attack is a fundamentally different artifact:
codegen/disassembly-backed safe-Rust load/test shape, or generated helper code
with proof that LLVM emits a better equality scan while preserving first
difference ordering. That artifact must come before a source edit.

## Behavior Proof

No source was edited.

Source hashes:

- `crates/frankenlibc-core/src/string/mem.rs`: `561924f9cec259aaeb5f38c20cc40325b18b6eea2a2ca52cf6d3cb1ea78d79dd`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`

Isomorphism:

- ordering/tie-breaking: unchanged by construction; first-difference ordering remains in the existing implementation
- floating-point: N/A
- RNG: not used
- golden output: existing `memcmp_golden_output_sha256` corpus remains unchanged; no new generated output was introduced

## Next Route

Route away from `memcmp_4096` source micro-levers until a generated
codegen/disassembly artifact identifies a new safe-Rust primitive. Continue the
campaign with another profile-backed unowned residual while that artifact is
prepared.
