# bd-2g7oyh.431 - memchr_absent exact-4096 dispatch rejection

Date: 2026-06-15
Agent: BoldFalcon
Target: `glibc_baseline_memchr_absent`
Worker: `vmi1227854`

## Profile-backed target

Pass 131 broad routing on pushed head `0ffdc4d7a` showed a material `memchr_absent` residual:

- FrankenLibC p50/mean: `29.641/33.189 ns`
- Host p50/mean: `23.492/26.200 ns`

Focused same-worker baseline reproduced the gap:

- FrankenLibC Criterion: `[27.854 ns 28.546 ns 29.216 ns]`
- FrankenLibC p50/mean: `29.424/28.907 ns`
- Host Criterion: `[20.112 ns 20.566 ns 21.073 ns]`
- Host p50/mean: `21.457/23.182 ns`

Prior no-retry families: panel-width changes, wider folded blocks, indexed folded scans, SWAR word-group scans, resolver retuning, and public-wrapper inlining. This candidate was a different exact-shape dispatch.

## One tested lever

Tested an exact `count == 4096` dispatch that used the same folded SIMD predicate and first-match resolver as the generic path but skipped the generic loop/tail machinery for the profiled shape.

## Behavior proof

RCH `cargo test -j 1 -p frankenlibc-core --lib memchr -- --nocapture --test-threads=1` passed 10/10 filtered tests, including:

- `memchr_golden_output_sha256`
- `prop_memchr_matches_scalar_position`
- `test_memchr_folded_simd_block_resolves_first_match`
- `test_memchr_simd_chunk_resolves_first_match`

Preserved by proof: first-match ordering, absent-result semantics, `n == 0`, clamped `n`, 4096 absent and boundary-hit golden cases, wide memchr behavior, floating-point behavior, RNG behavior, allocation behavior, errno behavior, and locale behavior.

## Post-benchmark

RCH post benchmark with the same focused filter and sample size:

- Candidate FrankenLibC Criterion: `[28.831 ns 29.180 ns 29.581 ns]`
- Candidate FrankenLibC p50/mean: `28.645/30.144 ns`
- Host Criterion: `[21.247 ns 21.700 ns 22.186 ns]`
- Host p50/mean: `20.946/22.164 ns`

Same-worker self delta vs focused baseline:

- p50: `29.424 -> 28.645 ns`, `2.6%` lower
- mean: `28.907 -> 30.144 ns`, `4.3%` slower
- Criterion center: `28.546 -> 29.180 ns`, `2.2%` slower

The p50-only movement is not enough to keep because mean and Criterion center regressed.

## Validation and restore

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`: passed before benchmark
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs`: passed before benchmark
- Source restored after rejection; no production source change is retained.

Restored SHAs:

- `crates/frankenlibc-core/src/string/mem.rs`: `088d2f0f8560cb76be215f584ef2adbffe9fae5135b28045655e2bf23cbbb14c`
- `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`

## Verdict

REJECTED-RESTORED.

Score: `0.0`.

Do not retry exact-4096 dispatch or loop/tail rearrangement for `memchr_absent`. The next `memchr_absent` route must be a materially different generated/vector primitive, not another surface loop-shape change.
