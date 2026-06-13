# bd-w7mtzu - wcstombs 4-byte packed SIMD encode keep

Date: 2026-06-13
Agent: BoldFalcon
Bead: `bd-w7mtzu`
Lever: packed four-wide UTF-8 4-byte encode window in `wcstombs`
Verdict: KEPT
Score: `(Impact 5.0 x Confidence 5.0) / Effort 2.0 = 12.5`

## Target

After the retained 2-byte, 3-byte decode, and 3-byte encode windows, the
remaining profiled wchar residual was the astral 4-byte lane. A focused
Criterion row was added before the production edit for both directions:

- `wchar_mbstowcs/astral_4byte`
- `wchar_wcstombs/astral_4byte`

The baseline selected encode as the next lever: `wcstombs/astral_4byte`
was slower than decode and still scalar per codepoint.

## Recommendation Contract

- Change: add a fixed-width packed byte-lane SIMD encoder for scalar
  `wctomb`'s RFC 2279 4-byte branch.
- Failure signature evidence: same-worker `vmi1153651` Criterion baseline
  showed `wchar_wcstombs/astral_4byte` middle `17.148 us` for 1024 codepoints.
- Mapped primitive: SIMD batching plus explicit UTF-8 state/range automaton.
- EV score: `(Impact 5 x Confidence 5 x Reuse 2) / (Effort 2 x Friction 1) = 25`.
- Relevance score: 5.0, directly targets the measured scalar hot lane.
- Primary risk: accepting or rejecting a different codepoint set than scalar
  `wctomb`. Countermeasure: SIMD path is gated to `0x1_0000..0x20_0000`, the
  exact scalar 4-byte branch, with all other values falling back to scalar.
- Budgeted mode: one fixed 4-codepoint window per iteration; no adaptive state.
- Fallback trigger: any mixed-width, NUL, short-output, 2/3-byte, 5/6-byte, or
  invalid window breaks to the scalar `wctomb` step.
- Baseline comparator: same-worker Criterion baseline on `vmi1153651`.
- Rollback: revert the single commit that adds the 4-byte encode window.
- Verification artifacts: core scalar-isomorphism, live-glibc differential,
  golden SHA reentry, same-worker Criterion before/after, touched-file rustfmt,
  `git diff --check`.

## Baseline

RCH command:

```text
env RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1153651 RCH_VISIBILITY=summary \
  RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  cargo bench -j 1 -p frankenlibc-bench --bench wchar_bench -- \
  astral_4byte --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

Baseline on `vmi1153651`:

```text
wchar_mbstowcs/astral_4byte
  [11.407 us 12.128 us 12.874 us]
  [303.43 MiB/s 322.09 MiB/s 342.45 MiB/s]

wchar_wcstombs/astral_4byte
  [16.014 us 17.148 us 18.625 us]
  [54.981 Melem/s 59.715 Melem/s 63.942 Melem/s]
```

## Change

`wcstombs` now has a 4-codepoint SIMD encode window after the 3-byte path:

- Range gate: all four `u32` codepoints must be in `0x1_0000..0x20_0000`.
- Byte lanes:
  - `0xF0 | (wc >> 18)`
  - `0x80 | ((wc >> 12) & 0x3F)`
  - `0x80 | ((wc >> 6) & 0x3F)`
  - `0x80 | (wc & 0x3F)`
- Packing: `simd_swizzle!` interleaves the four byte lanes into one `u8x16`.
- Store: one `copy_to_slice` writes the 16-byte window.

This is one lever: it does not change 4-byte decode, ASCII, 2-byte, 3-byte,
5/6-byte, invalid, NUL, or short-output scalar behavior.

## Isomorphism

- Ordering preserved: output byte triples/quads are packed in source order.
- Tie-breaking unchanged: not applicable.
- Floating point: not involved.
- RNG seeds: unchanged/not involved.
- Error behavior: unchanged. The SIMD path fires only for scalar `wctomb`'s
  existing 4-byte branch. Surrogates, out-of-range values, 5/6-byte values,
  NULs, mixed-width windows, and insufficient output capacity use scalar
  `wctomb`.
- Truncation behavior: unchanged. The SIMD path requires 16 output bytes before
  firing; otherwise scalar handles exact remaining capacity.

## Proof

Local:

- `cargo test -j 1 -p frankenlibc-core --lib wcstombs_simd_isomorphic_to_scalar -- --nocapture --test-threads=1`: passed.
- `cargo test -j 1 -p frankenlibc-abi --test conformance_diff_wcstombs_simd -- --nocapture --test-threads=1`: passed.
- `cargo test -j 1 -p frankenlibc-abi --test golden_wchar_conv_reentry -- --nocapture --test-threads=1`: passed.
- `rustfmt --check crates/frankenlibc-core/src/string/wchar.rs crates/frankenlibc-abi/tests/conformance_diff_wcstombs_simd.rs crates/frankenlibc-bench/benches/wchar_bench.rs`: passed.
- `cargo check -j 1 -p frankenlibc-core --lib`: passed.
- `cargo check -j 1 -p frankenlibc-abi --test conformance_diff_wcstombs_simd`: passed with the existing `wchar_abi.rs` `work_local` unused-assignment warning.
- `cargo check -j 1 -p frankenlibc-bench --bench wchar_bench`: passed.
- `git diff --check`: passed.

RCH `vmi1153651`:

- `cargo test -j 1 -p frankenlibc-core --lib wcstombs_simd_isomorphic_to_scalar -- --nocapture --test-threads=1`: passed.
- `cargo test -j 1 -p frankenlibc-abi --test conformance_diff_wcstombs_simd -- --nocapture --test-threads=1`: passed.
- `cargo test -j 1 -p frankenlibc-abi --test golden_wchar_conv_reentry -- --nocapture --test-threads=1`: passed.
- Golden SHA: `mbstowcs wide sha256=e52563fe0c036cc2d97d9b14a28d8d0e3adeec307686eecf8122466ca95dab50`.
- Golden SHA: `wcstombs back sha256=5f71c2382d1655e56994e4022f3e88be237d22350f6af9bd744680ec108aad6e`.

Known environment noise:

- RCH and local builds report the existing missing SMT solver warning.
- ABI builds report the existing `wchar_abi.rs` `work_local` unused-assignment warning.
- Focused `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings`
  remains blocked by pre-existing lint debt in `math/exp.rs`, `stdlib/sort.rs`,
  `string/fnmatch.rs`, and `string/regex.rs`. No reported clippy error was in
  this pass's touched wchar encoder/test/bench files.

## Post

Same-worker RCH post on `vmi1153651`, same command:

```text
wchar_mbstowcs/astral_4byte
  [10.735 us 10.994 us 11.304 us]
  [345.56 MiB/s 355.29 MiB/s 363.88 MiB/s]

wchar_wcstombs/astral_4byte
  [918.85 ns 997.60 ns 1.0930 us]
  [936.85 Melem/s 1.0265 Gelem/s 1.1144 Gelem/s]
```

Encode improvement:

- Middle estimate: `17.148 us -> 997.60 ns`, `17.19x` faster.
- Per-codepoint middle estimate: `16.746 ns/wc -> 0.974 ns/wc`.
- Throughput middle estimate: `59.715 Melem/s -> 1.0265 Gelem/s`.

## Remaining

`bd-w7mtzu` should remain open for the 4-byte `mbstowcs` decode lane, which is
still scalar and measured at `12.128 us` baseline / `10.994 us` post-control on
this run. Re-profile it separately before changing decode.
