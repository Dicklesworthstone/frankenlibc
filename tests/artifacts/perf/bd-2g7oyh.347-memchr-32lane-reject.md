# bd-2g7oyh.347 memchr 32-lane folded probe rejection

Date: 2026-06-11
Agent: BoldFalcon
Scope: `crates/frankenlibc-core/src/string/mem.rs`

## Target

Pass 75 selected `glibc_baseline_memchr_absent` from the post-pass-74 broad
RCH profile on `vmi1227854`, after excluding peer-owned `pow` and `strncmp`
lanes. The broad row showed FrankenLibC slower for a 4096-byte absent-byte
scan:

| row | FrankenLibC p50 ns | host p50 ns | FrankenLibC mean ns | host mean ns |
| --- | ---: | ---: | ---: | ---: |
| broad `memchr_absent` | 27.597 | 22.688 | 29.678 | 28.986 |

The lane has many prior rejected microfamilies, so this pass required a fresh
focused gate before editing.

## Focused Baseline

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
rch exec -v -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_BUILD_JOBS=2 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-347-memchr-absent-baseline-target \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memchr_absent --noplot --sample-size 50 \
--warm-up-time 1 --measurement-time 3
```

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 27.963 | 31.293 | 31.621 | 55.000 |
| host glibc | 19.898 | 21.156 | 25.694 | 45.500 |

## Lever Attempted

The current source uses a four-panel `Simd<u8, 64>` folded predicate over each
256-byte block. Blame shows that this was introduced after the accepted indexed
scan (`54126e7c`), by `d3a8d3e0 perf(string): widen memchr folded probe lanes`.

The candidate reversed only that lane-width change:

- remove `MEMCHR_WIDE_LANES`
- scan the same 256-byte block as eight `Simd<u8, 32>` equality panels
- keep the accepted indexed block loop
- keep the ordered `first_byte_simd_32` resolver for matching blocks
- keep 32-byte, 8-byte SWAR, and scalar tails unchanged

This was a panel-lowering test against the current worker behavior, not a
change to search semantics or block coverage.

## Codegen Probe

RCH does not treat `cargo rustc -- --emit=asm` as an offloadable compile command.
A remote `cargo bench --no-run` with `RUSTFLAGS=--emit=asm` compiled
successfully on `vmi1227854`, but the custom target artifact retrieval did not
materialize `.s` files locally, and direct SSH to the selected worker was denied
from this session. The candidate therefore proceeded as a history-backed
lane-width reversal and remained gated by the same-worker Criterion result.

## Behavior Proof

Local checks:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
git diff --check -- crates/frankenlibc-core/src/string/mem.rs .beads/issues.jsonl
```

RCH proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
rch exec -v -- env AGENT_NAME=BoldFalcon FRANKENLIBC_PROPTEST_CASES=4096 \
CARGO_BUILD_JOBS=2 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-347-memchr-proof-target \
cargo test -j 1 -p frankenlibc-core memchr --lib -- --nocapture --test-threads=1
```

Result: passed 10 focused tests, including:

- `string::mem::tests::memchr_golden_output_sha256`
- `string::mem::tests::prop_memchr_matches_scalar_position`
- folded/SIMD first-match ordering tests
- `wmemchr` parity tests

Golden memchr corpus SHA-256 stayed:
`04930b6afad5d9eb3047ad0fd21c4db13061e93ee506bcf740787790f8ae3500`.

Isomorphism:

- Ordering/tie-breaking: unchanged; matching blocks still resolve through the
  existing 32-byte low-to-high mask resolver.
- Bounded `n`: unchanged; `count = n.min(haystack.len())`.
- Floating point and RNG: not applicable.
- Error behavior: absent, found, and zero-length cases unchanged by the proof.

## Post Benchmark

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
rch exec -v -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_BUILD_JOBS=2 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-347-memchr-absent-post-target \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memchr_absent --noplot --sample-size 50 \
--warm-up-time 1 --measurement-time 3
```

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC candidate | 28.259 | 30.092 | 31.884 | 60.000 |
| host glibc | 20.237 | 21.837 | 25.702 | 50.000 |

Compared with the focused baseline, the candidate regressed p50
`27.963 -> 28.259 ns` and improved mean only `31.293 -> 30.092 ns`.

## Decision

Rejected and source restored.

Score: `(Impact 0 * Confidence 4) / Effort 2 = 0.0`.

No source change is retained. Do not retry `memchr_absent` panel-width reversal,
folded-panel widening, scalar SWAR wordgroups, or first-lane resolver retuning.
The next `memchr` route needs a genuinely different generated/codegen-backed
primitive; otherwise re-profile and select another unowned hotspot.
