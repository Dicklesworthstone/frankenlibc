# bd-2g7oyh.379 iconv UTF-8 -> single-byte SIMD decode window

Date: 2026-06-13T11:50:00Z
Agent: BoldFalcon

## Target

Profile-backed follow-up to `bd-48uzu9`: after the direct reverse-map table,
UTF-8 -> KOI8-R over clean Cyrillic 2-byte text still paid per-character UTF-8
decode overhead before the O(1) reverse lookup.

One retained lever in `crates/frankenlibc-core/src/iconv/mod.rs`: for
`UTF-8 -> single-byte target` descriptors with a reverse map, decode eight
clean 2-byte UTF-8 code points from a 16-byte portable-SIMD window, reverse-map
all eight scalars, and commit the output bytes only if every lane is valid and
representable. ASCII, 3-byte, malformed, short, unrepresentable, and no-space
cases fall through to the existing scalar/generic body.

## Baseline

Clean-HEAD worktree: `/data/projects/.scratch/frankenlibc-bd-2g7oyh-379-clean-20260613T1123`

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
| `iconv_utf8_to_koi8r/ascii_1k` | `[36.337 ns 37.554 ns 38.460 ns]` |
| `iconv_utf8_cyrillic_to_koi8r/cyrillic_1k` | `[4.1246 us 4.3193 us 4.5193 us]` |

## Proof

Ordering/tie-breaking: unchanged. The SIMD path only handles a clean run of
eight 2-byte UTF-8 scalars and commits atomically after validating all lead and
continuation lanes and all reverse-map outputs. On any failure it leaves
`in_pos`/`out_pos` unchanged and falls through to the existing scalar/generic
body, preserving EILSEQ/EINVAL/E2BIG ordering and stop positions.

Floating-point: N/A.

RNG: N/A.

Golden SHA:

`iconv_utf8_to_koi8r_golden_sha256` stayed
`05ea74b960f361549e1add14afdf2a3ba6c48df9229b0687b0a0e3c880e65fbb`.

RCH proof commands and results:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo test -j 1 -p frankenlibc-core --lib \
  iconv_ascii_fast_path_isomorphic_to_scalar -- --nocapture --test-threads=1
```

Result: passed 1/1 on `vmi1227854`.

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo test -j 1 -p frankenlibc-abi --test golden_iconv_utf8_fastpath \
  -- --nocapture --test-threads=1
```

Result: passed 2/2 on `vmi1227854`; KOI8-R SHA matched.

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo test -j 1 -p frankenlibc-abi --test conformance_diff_iconv \
  diff_iconv_open_close_convert -- --nocapture --test-threads=1
```

Result: passed 1/1 on `vmi1153651`.

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo test -j 1 -p frankenlibc-abi --test iconv_differential_fuzz \
  iconv_differential_fuzz_vs_glibc -- --nocapture --test-threads=1
```

Result: passed 1/1 on `vmi1153651`; `42000 conversions, 0 divergences vs host glibc`.

Known unrelated warnings: remote builds report the existing missing SMT solver
warning, existing `string/regex.rs` `prefilter_skips` dead-code warning, and
existing `wchar_abi.rs` `work_local` unused-assignment warning.

## Post-benchmark

Same command as baseline, same worker: `vmi1227854`.

Post rows:

| row | interval |
| --- | --- |
| `iconv_utf8_to_koi8r/ascii_1k` | `[30.183 ns 31.519 ns 32.835 ns]` |
| `iconv_utf8_cyrillic_to_koi8r/cyrillic_1k` | `[1.3007 us 1.3443 us 1.3860 us]` |

Target improvement:

- Mean: `4.3193 us -> 1.3443 us` (`3.21x` faster, `68.9%` lower).
- Throughput: `226.09 MiB/s -> 726.46 MiB/s` (`3.21x` higher).
- ASCII control mean: `37.554 ns -> 31.519 ns`.
- Score: `(Impact 5 * Confidence 5) / Effort 2 = 12.5`.

Verdict: KEPT.
