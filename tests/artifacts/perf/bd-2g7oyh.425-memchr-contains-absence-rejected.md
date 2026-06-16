# bd-2g7oyh.425 - memchr_absent contains absence-certificate rejection

## Route

Current-head broad RCH profile on `vmi1227854` after `cbcb4dc41` selected
`glibc_baseline_memchr_absent` as a material string residual:

- FrankenLibC broad p50/mean: `30.284/32.665 ns`
- host glibc broad p50/mean: `21.837/22.876 ns`

Prior no-retry families for this lane: panel-width changes, wider folded blocks,
indexed/SWAR folded scans, resolver retuning, public wrapper inlining,
exact-4096 dispatch, and loop/tail rearrangement.

## Focused Baseline

RCH worker: `vmi1227854`

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-425-memchr-baseline-20260616T0241-target CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-425-memchr-baseline-20260616T0241-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memchr_absent --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Results:

- FrankenLibC Criterion: `[28.201 ns 28.578 ns 28.939 ns]`
- FrankenLibC p50/mean: `28.090/29.230 ns`
- host glibc Criterion: `[20.471 ns 21.163 ns 21.961 ns]`
- host glibc p50/mean: `23.892/23.194 ns`

The focused gap reproduced and justified one source lever.

## Candidate

One lever:

```rust
if count == 4096 && !hs.contains(&needle) {
    return None;
}
```

The candidate was an exact 4096-byte absence certificate using the standard
slice search backend over the same `haystack[..count]` window. Present-byte
cases fell through to the existing ordered first-match resolver; absent cases
returned `None` only after the backend proved the byte was absent.

## Behavior Proof

RCH worker: `vmi1227854`

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-425-memchr-proof-20260616T0247-target cargo test -j 1 -p frankenlibc-core --lib memchr -- --nocapture --test-threads=1
```

Result: passed 10/10 filtered memchr and wmemchr tests, including:

- `memchr_golden_output_sha256`
- `prop_memchr_matches_scalar_position`
- `test_memchr_folded_simd_block_resolves_first_match`
- `test_memchr_simd_chunk_resolves_first_match`
- absent, found, zero-length, and wide-character coverage

Isomorphism proof: the candidate reads exactly the same clamped
`haystack[..count]` window. If `contains` finds no needle, the original resolver
would also have exhausted the same window and returned `None`. If `contains`
finds a needle, the candidate falls through, so first-match ordering and
tie-breaking remain the existing resolver's responsibility. There is no
floating-point, RNG, allocation, errno, locale, or output-order surface in this
function.

Golden fixture SHA after source restoration:

```text
94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4  tests/conformance/fixtures/string_memory_full.json
```

## Post Benchmark

RCH worker: `vmi1227854`

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-425-memchr-post-20260616T0249-target CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-425-memchr-post-20260616T0249-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memchr_absent --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Results:

- Candidate FrankenLibC Criterion: `[266.99 ns 269.60 ns 272.20 ns]`
- Candidate FrankenLibC p50/mean: `268.731/273.128 ns`
- host glibc Criterion: `[22.576 ns 23.490 ns 24.210 ns]`
- host glibc p50/mean: `20.943/23.114 ns`

Same-worker self delta:

- Criterion center: `28.578 -> 269.600 ns`
- p50: `28.090 -> 268.731 ns`
- mean: `29.230 -> 273.128 ns`

## Verdict

Rejected and source restored. Score: `0.0`.

Restored source SHA:

```text
088d2f0f8560cb76be215f584ef2adbffe9fae5135b28045655e2bf23cbbb14c  crates/frankenlibc-core/src/string/mem.rs
```

Do not retry standard slice `contains` as an absence certificate for
`memchr_absent`. The next admissible `memchr_absent` route needs a genuinely
different generated/vector primitive and a fresh focused same-worker gate.
