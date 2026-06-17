# bd-2g7oyh.469 pass187 memchr4096 absence certificate

Date: 2026-06-17T10:52:00Z

Head: `913e80cf0 chore(perf): route current head pass 186`

Reason: pass186 current-head routing selected `memchr_absent` as the largest clean residual: FrankenLibC `29.663 / 32.483 ns` p50/mean vs host `20.822 / 22.358`. Recent memchr attempts rejected folded-mask/control-mask/panel-width/codegen-only families, so this pass tested one deeper scan-shape primitive.

## Baseline

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass187-baseline-target-20260617T1042 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memchr_absent --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Log: `target/perf-logs/bd-2g7oyh-pass187-memchr-baseline.log`

Log SHA-256: `4ed7b90eec85025312b5354f932b6e2ad59688f64d738127b9844017f848f0de`

Rows:

| Impl | p50 ns/op | mean ns/op | Criterion interval |
| --- | ---: | ---: | --- |
| FrankenLibC | `29.927` | `33.439` | `[31.143 ns 31.941 ns 32.748 ns]` |
| host glibc | `20.541` | `21.590` | `[20.862 ns 21.348 ns 21.883 ns]` |

## Lever Kept

Add an exact-4096 whole-buffer absence certificate before the existing `memchr` folded-block scan:

- Accumulate equality masks over sixty-four 64-byte safe portable-SIMD chunks.
- Perform one final `hits.any()` reduction.
- Return `None` only when the entire exact-4096 prefix is certified absent.
- If any hit may exist, fall through to the existing low-to-high resolver, preserving first-match order.

This is a different dependency graph from the rejected local 256-byte folded mask/control-mask families: it removes per-256-byte horizontal reductions from the absent hot row and keeps positive-hit resolution unchanged.

## Behavior Proof

Focused proof command:

```bash
env CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass187-proof-target-20260617T1044 \
  cargo test -j 1 -p frankenlibc-core memchr -- --nocapture
```

Log: `target/perf-logs/bd-2g7oyh-pass187-memchr-tests.log`

Log SHA-256: `d1a53a67163bf021b6f70a200f2d155b877ad339361eac73a53090b38d7a9a6f`

Passed direct/golden guards:

- `test_memchr_found`, `test_memchr_not_found`, `glibc_memchr_n_zero_returns_none`
- `test_memchr_simd_chunk_resolves_first_match`
- `test_memchr_folded_simd_block_resolves_first_match`
- `prop_memchr_matches_scalar_position`
- `prop_memchr_finds_first_occurrence`
- inline `memchr_golden_output_sha256`: `04930b6afad5d9eb3047ad0fd21c4db13061e93ee506bcf740787790f8ae3500`
- external `golden_memchr_corpus_sha256`: `aec12be451b7b8803c8c57199f64dd2f40fc7c8894f3830e203eacaf0039f952`
- `wmemchr` sibling tests also remained green.

Isomorphism:

- First-match ordering: preserved because the certificate only returns on proven absence; any hit falls through to the existing ordered resolver.
- Absent result: exact equality-mask accumulation proves no byte equals `needle` in `haystack[..4096]`.
- `n` clamping/no-read-past: the new branch is guarded by `count == 4096` after `count = n.min(haystack.len())`; it scans only `hs = &haystack[..count]`.
- Tail and non-4096 behavior: unchanged; all other counts use the existing folded/panel/SWAR/tail paths.
- `memrchr`, substring callers, allocation/errno/locale/FP/RNG state: unchanged.

Source SHA-256 with the kept lever: `04795966abfaab92fb33447804ae206199ab945c31942da842568cb37799ee12`

## Post Benchmark

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass187-post-target-20260617T1047 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memchr_absent --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Log: `target/perf-logs/bd-2g7oyh-pass187-memchr-post.log`

Log SHA-256: `5cefd414d307d247faac9e0af2219a0368c340557d77dd90c3f08217928925e0`

Rows:

| Impl | p50 ns/op | mean ns/op | Criterion interval |
| --- | ---: | ---: | --- |
| FrankenLibC candidate | `23.794` | `27.119` | `[22.008 ns 22.458 ns 22.976 ns]` |
| host glibc | `21.400` | `23.212` | `[20.820 ns 21.353 ns 21.928 ns]` |

Improvement:

- FrankenLibC p50: `29.927 -> 23.794 ns`, `1.258x`
- FrankenLibC mean: `33.439 -> 27.119 ns`, `1.233x`
- Criterion centers separate cleanly: `31.941 ns -> 22.458 ns`

## Validation

Passed:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
git diff --check
env CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass187-check-target-20260617T1049 cargo check -j 1 -p frankenlibc-core --lib
```

`cargo check` log SHA-256: `b367ff22141ebd98cafeaf1c03b1aa3ad8cb2c3e49501a51e71f9a98bde7714f`

Attempted but blocked by existing unrelated lint debt:

```bash
env CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass187-clippy-target-20260617T1050 cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings
```

Clippy log SHA-256: `8aad129b6c2b2a499372fb3e7581f132c87ee5bbc707d6f543019cff53a4bd47`

The clippy failures are in pre-existing `iconv` and `resolv` code, not `crates/frankenlibc-core/src/string/mem.rs`.

## Verdict

KEPT. Score `8.0` (`Impact 3.0 x Confidence 4.0 / Effort 1.5`) because the focused row improves by `1.258x` p50 and `1.233x` mean with clean Criterion separation and strong memchr golden/property proof.

Next route: reprofile current head because bottlenecks shift. Do not repeat this exact-4096 absence-certificate lever; if `memchr_absent` remains material, a follow-up must target a different scan shape or a positive-hit/other-size path.
