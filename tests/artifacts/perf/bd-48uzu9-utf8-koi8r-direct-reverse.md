# bd-48uzu9 UTF-8 -> KOI8-R direct reverse lookup

Date: 2026-06-13T04:33:26Z
Agent: BoldFalcon

## Target

`bd-48uzu9` followed the partial UTF-8-source iconv fast path. The remaining
profile-backed residual was UTF-8 -> KOI8-R over Cyrillic text: the hot loop
decoded each 2-byte UTF-8 scalar, then encoded through `SingleByteReverse::lookup`
with a binary search over the single-byte target map.

One retained lever: add a small direct BMP-page table to `SingleByteReverse`.
ASCII still returns by identity, BMP codepoints hit `page_slot[cp >> 8]` plus a
256-byte page lookup, and the existing sorted `high_cp/high_byte` binary search
remains the fallback for non-BMP or uncached pages. The table is built from the
same canonical `decode_char` + `encode_char` round-trip used by the old map.

## Baseline

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 cargo bench -j 1 -p frankenlibc-bench \
  --bench iconv_bench -- 'iconv_utf8_cyrillic_to_koi8r|iconv_utf8_to_koi8r' \
  --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

Worker: `vmi1227854`.

Baseline rows:

| row | interval |
| --- | --- |
| `iconv_utf8_to_koi8r/ascii_1k` | `[25.911 ns 26.945 ns 28.034 ns]` |
| `iconv_utf8_cyrillic_to_koi8r/cyrillic_1k` | `[5.0284 us 5.2582 us 5.4892 us]` |

## Proof

Ordering/tie-breaking: unchanged. The direct table is populated only for
codepoints where the old canonical reverse map already returned the same output
byte. Missing entries fall through to the existing binary-search fallback, and
`encode_one` still delegates misses or no-space cases to `encode_char`, preserving
E2BIG vs EILSEQ ordering and stop positions.

Floating-point: N/A.

RNG: N/A.

Golden SHA:

`iconv_utf8_to_koi8r_golden_sha256` pins
`05ea74b960f361549e1add14afdf2a3ba6c48df9229b0687b0a0e3c880e65fbb` over a
deterministic ASCII+Cyrillic UTF-8 -> KOI8-R corpus.

RCH proof commands:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo test -j 1 -p frankenlibc-core --lib \
  iconv_ascii_fast_path_isomorphic_to_scalar -- --nocapture --test-threads=1
```

Result: passed 1/1; the optimized loop matched the scalar
`decode_char`/`encode_char` reference across UTF-8, ASCII, Latin-1, KOI8-R, and
CP1251 corpora.

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo test -j 1 -p frankenlibc-abi --test golden_iconv_utf8_fastpath \
  -- --nocapture --test-threads=1
```

Result: passed 2/2; existing UTF-16/32 pins unchanged and KOI8-R SHA matched.

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo test -j 1 -p frankenlibc-abi --test conformance_diff_iconv \
  diff_iconv_open_close_convert -- --nocapture --test-threads=1
```

Result: passed 1/1.

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo test -j 1 -p frankenlibc-abi --test iconv_differential_fuzz \
  iconv_differential_fuzz_vs_glibc -- --nocapture --test-threads=1
```

Result: passed 1/1; `42000 conversions, 0 divergences vs host glibc`.

Formatting: `rustfmt --edition 2024 --check` passed for
`crates/frankenlibc-core/src/iconv/mod.rs` and
`crates/frankenlibc-abi/tests/golden_iconv_utf8_fastpath.rs`.

Known unrelated gates: crate-wide `cargo fmt -p frankenlibc-core --check` is
blocked by pre-existing formatting drift outside this lever. RCH compiles report
existing warnings in `string/regex.rs` (`prefilter_skips`) and
`wchar_abi.rs` (`work_local`), not introduced by this change.

## Post-benchmark

Same command and worker: `vmi1227854`.

Post rows:

| row | interval |
| --- | --- |
| `iconv_utf8_to_koi8r/ascii_1k` | `[27.892 ns 29.183 ns 30.526 ns]` |
| `iconv_utf8_cyrillic_to_koi8r/cyrillic_1k` | `[3.2914 us 3.4282 us 3.5695 us]` |

Target improvement:

- Mean: `5.2582 us -> 3.4282 us` (`34.8%` faster).
- Throughput: `185.72 MiB/s -> 284.86 MiB/s` (`53.4%` higher).
- Score: `(Impact 3.5 * Confidence 5) / Effort 2 = 8.75`.

Verdict: KEPT.

## Notes

During this run, a concurrent exp10f lane left tracked changes in
`crates/frankenlibc-core/src/math/float32.rs` and
`crates/frankenlibc-abi/tests/conformance_diff_math.rs`. Those files are
unrelated to this iconv lever and are intentionally not part of this proof or
commit.
