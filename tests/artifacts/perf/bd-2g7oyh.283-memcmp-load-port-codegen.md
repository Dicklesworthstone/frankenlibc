# bd-2g7oyh.283 memcmp load-port / ISA diagnostic

Date: 2026-06-09
Agent: BoldFalcon
Scope: `crates/frankenlibc-core/src/string/mem.rs`

## Target

`bd-2g7oyh.283` followed the rejected `bd-2g7oyh.282` memcmp_4096
work. The bead hypothesis was that the equal-buffer kernel was pinned near one
AVX2 load stream while host glibc reached the two-load-port L1 ceiling.

The live code at this pass already uses:

- exact-16 mask resolution,
- exact-256 equality certificate,
- a 128-byte folded `Simd<u8, 32>` equal-block probe,
- ordered 32-byte panel and byte fallback for first-difference semantics.

Prior rejected families include folded-block widening, broadword probes,
64-lane rank/select masks, exact-size branchbacks/foldbacks, inline-only
visibility, as-chunks/array-reference loads, branchless multi-accumulators, and
manual copy-panel analogues.

## Fresh RCH baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=120 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd283-baseline-20260609 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memcmp_4096 --noplot --sample-size 40 --warm-up-time 1 \
  --measurement-time 3
```

RCH selected `vmi1227854`.

Result:

| impl | p50 ns | mean ns | p95 ns | p99 ns | criterion throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | 48.019 | 53.738 | 52.769 | 100.000 | 80.169 GiB/s |
| host glibc | 43.116 | 46.236 | 57.500 | 81.022 | 89.204 GiB/s |

This focused row is a baseline miss for the bead's original gap: current
FrankenLibC is only `1.11x` slower at p50 and `1.16x` slower at mean, not the
previous `~1.55x` load-port-sized residual.

## Codegen / ISA gates checked

- The repo already sets `-Ctarget-feature=+avx2,+fma` globally in
  `.cargo/config.toml`, so the focused RCH bench was an AVX2 build.
- `rch workers capabilities --json` reports Rust/runtime and host capacity, but
  it does not expose CPU ISA flags.
- Direct SSH to the selected worker failed with `Permission denied
  (publickey,password)`, so CPU flags could not be read out-of-band.
- `rch diagnose -- cargo asm frankenlibc_core::string::mem::memcmp` and
  `rch diagnose -- cargo rustc -p frankenlibc-core --lib --profile bench --
  --emit=asm` both reported `cargo subcommand not interceptable`; RCH would not
  route those disassembly commands.

Because the admissible next levers all require pre-edit disassembly or IR proof,
no source edit was made.

## Sidecar candidate audit

The repeated-skill explorer sidecar identified three remaining candidate
families. All are blocked on the same codegen gate before editing:

1. XOR/test-zero instruction selection: replace the current
   `simd_ne(...).any()` predicate with `a ^ b` plus OR/test-zero while keeping
   the 128-byte block shape and existing resolver. This is behavior-isomorphic,
   but it must first prove materially different assembly such as `vpxor`/`vpor`
   plus `vptest` with no worse horizontal reduction.
2. `slice::as_simd::<32>()` middle loop: only admissible if it proves a real
   bounds-check or alignment-codegen difference from the already rejected
   as-chunks/array-reference family.
3. AVX-512BW/VL diagnostic: only admissible as a gated ISA sidecar if worker
   hardware support and disassembly show useful mask-test or wider-lane lowering
   without changing the default libc ISA baseline.

## Isomorphism

No source change was kept.

- Ordering: unchanged by construction.
- First-difference tie-breaking: unchanged by construction.
- Floating-point: N/A.
- RNG: N/A.
- Golden output: unchanged by construction; the pinned source golden remains
  `458c0ae019afaffccbfc5a6aacfeb4713dab611eac4b6257398016a7eae45ef9`.

## Verdict

NO-CODE REJECTED, Score `0.0`.

The fresh focused baseline did not reproduce the original load-port-sized gap,
and the only still-admissible source levers require disassembly/ISA evidence
that RCH could not provide in this setup. No `mem.rs` change was made.

Next route: reprofile before selecting the next target. If memcmp reappears as
a real same-worker residual, first add a purpose-built assembly/IR extraction
path that RCH can route, then test the XOR/test-zero instruction-selection
lever as exactly one change. Otherwise move to the next profile-backed
`[perf]` bead.
