# bd-tb3rk7 wcsrchr safe-SIMD clean-panel skip

## Profile target

- Bead: `bd-tb3rk7` (tracker wording to be corrected from the temporary `memchr` title
  before closeout).
- Target: `crates/frankenlibc-core/src/string/wide.rs::wcsrchr` for non-NUL absent scans.
- Scenario: wide string contains no target and no early terminator until the end, so the
  scan must traverse the full slice while preserving last-match-before-NUL semantics.
- Baseline command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- 'memchr_absent|memrchr_absent|memcmp|memset|wmem|wcs' --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Baseline worker: `vmi1227854`.

| Bench | p50 ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: |
| `wcsrchr_absent_4096` | 1189.980 | 1426.600 | 1550.883 |

The same profile put `wcsrchr_absent_4096` above the adjacent wide scan family:
`wcschr_absent_4096` p50 `530.804`, `wmemcmp_equal_4096` p50 `498.849`,
`wcsstr_absent_4096` p50 `460.162`, `wcslen_4096` p50 `331.887`,
`wmemrchr_absent_4096` p50 `319.466`, and `wmemchr_absent_4096` p50 `304.918`.

## Alien primitive

Canonical source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` section 7.7,
Swiss Tables SIMD group probes over a compact control plane.

- Primitive: vectorized membership probe over 8 contiguous `u32` lanes, using the wide
  string itself as the control plane.
- Runtime artifact: safe-Rust `Simd<u32, 8>` equality probes for `c` and NUL through the
  existing `has_wide_or_nul_simd` helper.
- Fallback: exact scalar left-to-right candidate resolution inside any panel containing
  `c` or NUL; reject if the golden transcript changes or post-RCH p50 fails Score >= 2.0.
- EV score: Impact 5 x Confidence 4 / Effort 2 = 10.0.

## One lever

The `c != 0` `wcsrchr` scan now walks `chunks_exact(WIDE_SIMD_LANES)` and skips a full
8-lane panel only when `has_wide_or_nul_simd(chunk, c)` proves it contains neither the
target nor NUL. Candidate panels and the remainder still resolve scalar in increasing
index order. The `c == 0` branch is unchanged.

The validation-only cleanup in this file removed one unused `wmemcmp` counter and replaced
the `wmemrchr` front remainder loop with the equivalent `Iterator::find` form required by
`-D warnings`; neither change alters algorithmic behavior.

## Isomorphism proof

- NUL ordering is preserved: no panel containing NUL is skipped, and candidate panels test
  each lane for NUL before considering later lanes.
- Last-match tie-breaking is preserved: matching lanes before the terminator update `last`
  in increasing index order, so the final value remains the greatest index before NUL.
- Absent behavior is preserved: NUL-free, target-free panels can only advance the base
  offset; they could not have changed `last` or terminated in the scalar implementation.
- Tail behavior is preserved: `chunks.remainder()` covers exactly the same suffix the old
  loop covered after its full panels.
- `c == 0` behavior is unchanged, including returning `Some(s.len())` for unterminated
  inputs.
- Floating-point behavior is N/A. RNG behavior is N/A.

## Golden behavior

Pre-edit behavior command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core wcsrchr -- --nocapture --test-threads=1
```

Pre-edit result: 6 existing `wcsrchr` tests passed on `vmi1264463`.

Pre-edit test-line SHA256:

```text
fd2bde19273a0dea5b7c0b6526135f3470f4eeebc5764f5b259eb9a34043e258
```

Post-edit behavior command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core wcsrchr -- --nocapture --test-threads=1
```

Post-edit result: 7 `wcsrchr` tests passed on `vmi1149989`, including
`test_wcsrchr_panel_stops_at_nul_before_later_match`.

Post-edit full test-line SHA256:

```text
752ec9832776905e24b2c633be4b01612d4d137146c0121ed22a194ee0014a8a
```

The added test pins the candidate-panel ordering case where a previous match exists before
a panel NUL and later matching lanes after that NUL must remain ignored.

## Post benchmark

Post command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- wcsrchr_absent --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Post worker: `vmi1149989`.

| Bench | Baseline p50 ns/op | Post p50 ns/op | Speedup |
| --- | ---: | ---: | ---: |
| `wcsrchr_absent_4096` | 1189.980 | 658.641 | 1.81x |

Score: Impact 5 x Confidence 4 / Effort 2 = 10.0, kept. Median latency dropped by
44.6%; p95 improved from `1426.600` to `1240.550`.

Confirmation command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- wcsrchr_absent --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Confirmation worker: `vmi1293453`.

| Bench | Baseline p50 ns/op | Confirmed p50 ns/op | Confirmed p95 ns/op | Confirmed p99 ns/op | Speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| `wcsrchr_absent_4096` | 1189.980 | 531.000 | 629.081 | 1017.782 | 2.24x |

The earlier p99 outlier did not repeat; confirmation p95 and p99 both beat the baseline.

## Validation

- `cargo fmt --check -p frankenlibc-core`: passed locally.
- `git diff --check -- crates/frankenlibc-core/src/string/wide.rs`: passed locally.
- `ubs crates/frankenlibc-core/src/string/wide.rs`: no critical findings.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets`: passed on `vmi1227854`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: passed on `vmi1167313`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core string::wide::tests:: --lib -- --nocapture --test-threads=1`: passed 73/73 on `vmi1293453`.

## Source

- Pre `wide.rs` sha256: `a0e047e421aeeccef81b9e49d450e50f3da8f66d9674ee5e9d2417966301f7b1`
- Post `wide.rs` sha256: `af447fb8724562acad04c76ba5ca5c82fa272cf1899159e0d3edc2d5e630371a`
