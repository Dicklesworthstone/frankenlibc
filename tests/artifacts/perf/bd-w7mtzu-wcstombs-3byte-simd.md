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
