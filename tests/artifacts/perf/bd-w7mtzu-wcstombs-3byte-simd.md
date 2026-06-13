# bd-w7mtzu: wcstombs 3-byte SIMD encode rejection

Date: 2026-06-13
Agent: BoldFalcon
Bead: `bd-w7mtzu`
Lever: portable-SIMD 4-wide UTF-8 3-byte encode window in `wcstombs`
Verdict: REJECTED
Score: 0.0

## Target

`bd-w7mtzu` remains open after the retained 2-byte decode, 2-byte encode, and
3-byte `mbstowcs` decode wins. The next obvious remaining lane was 3-byte BMP
`wcstombs` encode for CJK/Euro/snowman-style codepoints.

The tested lever added a range-validated SIMD path for four
`0x0800..0xFFFF` non-surrogate `wchar_t` values. It computed the three UTF-8
output byte classes with `Simd<u32, 4>`, converted them to byte arrays, then
stored the four 3-byte encodings into the destination buffer. ASCII, 2-byte,
surrogate, 4+ byte, NUL, and short-output cases fell back to the existing
scalar `wctomb` path.

## Baseline

RCH selected and ran on `vmi1153651` with a clean detached worktree at
`b4c28774`:

```text
env RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  cargo bench -j 1 -p frankenlibc-bench --bench wchar_bench -- \
  'wchar_wcstombs/(mixed_utf8|ascii_1k)' --noplot --sample-size 60 \
  --warm-up-time 1 --measurement-time 3
```

Baseline:

```text
wchar_wcstombs/ascii_1k
  [206.06 ns 213.39 ns 221.36 ns]

wchar_wcstombs/mixed_utf8
  [7.6085 us 8.0783 us 8.7669 us]
```

## Post-Candidate Benchmark

Same worker `vmi1153651`, same command, candidate applied only in the detached
worktree:

```text
wchar_wcstombs/ascii_1k
  [245.35 ns 271.25 ns 310.74 ns]

wchar_wcstombs/mixed_utf8
  [10.990 us 11.832 us 12.939 us]
```

The decisive row regressed by `8.0783 us -> 11.832 us` (`46.5%` slower). The
ASCII control row also regressed (`213.39 ns -> 271.25 ns`). This fails the
Score >= 2.0 gate.

## Behavior / Isomorphism

No behavior-changing code is retained.

- Ordering preserved: N/A; candidate removed.
- Tie-breaking unchanged: N/A.
- Floating-point: N/A.
- RNG seeds: unchanged/N/A.
- Golden outputs: unchanged by construction; retained source diff for
  `crates/frankenlibc-core/src/string/wchar.rs` and
  `crates/frankenlibc-abi/tests/conformance_diff_wcstombs_simd.rs` is empty
  after restore.

## Restore Proof

The candidate hunk was removed from the production and fuzz files. The retained
commit is evidence-only; it does not alter `wcstombs` behavior.

Do not retry this exact primitive family:

- 4-wide `Simd<u32, 4>` 3-byte encode with `to_array()` extraction
- scalar per-lane 3-byte stores after SIMD byte-class computation
- widened fuzz-only 3-byte encode coverage without a different retained kernel

Next admissible routes should use a materially different primitive: a packed
byte-lane encoder that constructs one `u8x16`/shuffle store with a masked
12-byte copy, a shared UTF-8 encode microkernel reused by `wcsrtombs`, or the
4-byte astral lane if a focused profile shows it is now dominant.
---

# bd-w7mtzu - wcstombs 3-byte packed SIMD encode keep

## Target

- Bead: `bd-w7mtzu`
- Lane: `wcstombs` pure 3-byte BMP / CJK encode.
- Baseline/post worker: `vmi1153651`
- Lever: encode a clean 4-codepoint BMP non-surrogate window into four UTF-8 triples with portable SIMD, falling back to the existing scalar `wctomb` path for every ASCII, 2-byte, astral, surrogate, out-of-range, NUL, short-output, or mixed-width window.

This retained route is materially different from the rejected scalar-store
candidate above: it computes lead/middle/tail byte lanes, packs them through
`simd_swizzle!` into one `u8x16`, and copies the first 12 bytes. It does not
retry scalar per-lane stores after SIMD byte-class computation.

## Baseline

Focused Criterion case was added to `wchar_bench` before the production encoder change.

RCH baseline on `vmi1153651`:

- Command: `cargo bench -j 1 -p frankenlibc-bench --bench wchar_bench -- wchar_wcstombs/cjk_3byte`
- `wchar_wcstombs/cjk_3byte`: `[11.194 us 11.849 us 12.990 us]`
- Throughput: `[78.828 Melem/s 86.419 Melem/s 91.477 Melem/s]`
- Workload: 1024 CJK BMP codepoints, all 3-byte UTF-8 output.

## Isomorphism

- Output order is unchanged: the SIMD path writes `lead, middle, tail` bytes for each of four codepoints in source order.
- Error behavior is unchanged: the SIMD path only fires when all four codepoints are in `0x0800..=0xFFFF` and not in `0xD800..=0xDFFF`.
- NUL, ASCII, 2-byte, 4-byte astral, surrogate, out-of-range, mixed-window, and short-output cases fall through to the existing scalar `wctomb` step.
- Truncation behavior is unchanged: the SIMD path requires 12 output bytes before firing; otherwise scalar handles the exact remaining capacity.
- Floating point and RNG are not involved.

## Proof

Local:

- `cargo test -j 1 -p frankenlibc-core --lib wcstombs_simd_isomorphic_to_scalar -- --nocapture --test-threads=1`: passed.
- `cargo test -j 1 -p frankenlibc-abi --test conformance_diff_wcstombs_simd -- --nocapture --test-threads=1`: passed.
- `cargo test -j 1 -p frankenlibc-abi --test golden_wchar_conv_reentry -- --nocapture --test-threads=1`: passed.
- `rustfmt --check crates/frankenlibc-core/src/string/wchar.rs crates/frankenlibc-abi/tests/conformance_diff_wcstombs_simd.rs crates/frankenlibc-bench/benches/wchar_bench.rs`: passed.
- `cargo check -j 1 -p frankenlibc-core --lib`: passed.
- `cargo check -j 1 -p frankenlibc-abi --test conformance_diff_wcstombs_simd`: passed with the existing `wchar_abi.rs` `work_local` unused-assignment warning.
- `cargo check -j 1 -p frankenlibc-bench --bench wchar_bench`: passed.

RCH:

- `cargo test -j 1 -p frankenlibc-core --lib wcstombs_simd_isomorphic_to_scalar -- --nocapture --test-threads=1`: passed on `vmi1227854`.
- `cargo test -j 1 -p frankenlibc-abi --test conformance_diff_wcstombs_simd -- --nocapture --test-threads=1`: passed on `vmi1227854`.
- `cargo test -j 1 -p frankenlibc-abi --test golden_wchar_conv_reentry -- --nocapture --test-threads=1`: passed on `vmi1227854`.
- Golden SHA: `mbstowcs wide sha256=e52563fe0c036cc2d97d9b14a28d8d0e3adeec307686eecf8122466ca95dab50`.
- Golden SHA: `wcstombs back sha256=5f71c2382d1655e56994e4022f3e88be237d22350f6af9bd744680ec108aad6e`.

Known environment noise:

- RCH workers report the existing missing SMT solver warning.
- ABI builds report the existing `wchar_abi.rs` `work_local` unused-assignment warning.
- Focused `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings` remains blocked by pre-existing lint debt in `math/exp.rs`, `stdlib/sort.rs`, `string/fnmatch.rs`, and `string/regex.rs`; no reported clippy error was in this pass's touched wchar encoder/test/bench files.
- Package-wide `cargo fmt --check -p frankenlibc-core -p frankenlibc-abi -p frankenlibc-bench` remains blocked by unrelated existing formatting drift outside this pass; touched-file rustfmt passed.

## Post

RCH post on `vmi1153651`:

- Command: `cargo bench -j 1 -p frankenlibc-bench --bench wchar_bench -- wchar_wcstombs/cjk_3byte`
- `wchar_wcstombs/cjk_3byte`: `[966.19 ns 1.0170 us 1.0763 us]`
- Throughput: `[951.44 Melem/s 1.0069 Gelem/s 1.0598 Gelem/s]`

Same-worker improvement:

- Middle estimate: `11.849 us -> 1.0170 us`, `11.65x` faster.
- Per-codepoint middle estimate: `11.571 ns/wc -> 0.993 ns/wc`.
- Throughput middle estimate: `86.419 Melem/s -> 1.0069 Gelem/s`.

## Score

Kept. Score `(Impact 5.0 x Confidence 5.0) / Effort 2.0 = 12.5`.

Remaining route on `bd-w7mtzu`: 4-byte astral encode/decode paths remain open; do not call the bead fully closed until that lane is separately profiled and addressed.
