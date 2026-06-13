# bd-2g7oyh.365 - wcsrchr ABI portable-SIMD reverse scan

## Target

Profile-backed follow-on from `bd-2g7oyh.364`: `wcschr` had moved to the
page-contained `u32x8` c-or-NUL scanner, while `wcsrchr` still had a scalar
element loop for the strict unbounded ABI path.

The runtime lever is the `wide_last_before_nul_simd` path in
`crates/frankenlibc-abi/src/wchar_abi.rs`, already present in current `HEAD`
via the preceding wide-string perf series. This artifact pins the missing
focused proof, benchmark gate, and closeout evidence for the still-open bead.

## Baseline

Command:

```bash
RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-365-wcsrchr-baseline \
  cargo bench -j 1 -p frankenlibc-bench --features abi-bench --bench memset_abi_bench
```

RCH selected `vmi1153651`.

```text
wcsrchr (absent target -> full wide scan to NUL):
  wchars |      old(ns) |      abi(ns) |      old/abi
      16 |         11.8 |         45.9 |        0.26x
      64 |         44.1 |         91.3 |        0.48x
     256 |        188.0 |        285.2 |        0.66x
    1024 |        686.8 |        785.9 |        0.87x
    4096 |       2733.7 |       3503.7 |        0.78x
   16384 |      10983.5 |      19122.7 |        0.57x
   65536 |      44219.7 |      51201.0 |        0.86x
```

## Lever

`wcsrchr` strict/unbounded now uses `wide_last_before_nul_simd`: an aligned
8-lane `Simd<u32, 8>` c-or-NUL panel filter. Only panels containing either the
target or the terminator are resolved scalar, preserving exact result ordering.
The bounded hardened repair path remains scalar.

## Isomorphism Proof

- Ordering: windows with neither `c` nor NUL are skipped because they cannot
  affect either the latest match or string termination.
- Tie-breaking: flagged windows are resolved left-to-right; each target updates
  `last`, so repeated targets return the highest index before the first NUL.
- Terminator handling: `c == 0` delegates to the existing first-NUL scanner and
  returns the terminator pointer, matching `wcsrchr(s, L'\0')`.
- Bounds: the strict path uses the same 32-byte alignment discipline as
  `wcschr`; every vector load stays within one page before scalar resolution.
- Hardened mode: bounded repair behavior is unchanged and still scalar.
- Floating point and RNG: not involved.

Golden output SHA-256:

```text
3fb98cbeed206dcbbf6fa27007b4ac83bc76438ae30817652b8a07a340b54f77
```

## Proof

Command:

```bash
RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-365-wcsrchr-proof2 \
  cargo test -j 1 -p frankenlibc-abi --test conformance_diff_wcsrchr -- \
  --nocapture --test-threads=1
```

Result on `vmi1227854`: 3/3 passed.

The gate compares 5,120 host-glibc differential cases across alignment,
length, target, high `wchar_t` values, absent targets, repeated targets, and
`c == 0`, plus a guard-page no-overread test.

## Post-Benchmark

Command:

```bash
RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-365-wcsrchr-post-filtered \
  FRANKENLIBC_ABI_BENCH_ONLY=wcsrchr \
  cargo bench -j 1 -p frankenlibc-bench --features abi-bench --bench memset_abi_bench
```

Result on `vmi1227854`:

```text
wcsrchr (absent target -> full wide scan to NUL):
  wchars |      old(ns) |      abi(ns) |      old/abi
      16 |          5.3 |         13.0 |        0.41x
      64 |         21.6 |         16.4 |        1.31x
     256 |         88.3 |         18.7 |        4.71x
    1024 |        331.6 |         53.3 |        6.22x
    4096 |       1319.3 |        199.0 |        6.63x
   16384 |       5224.8 |        755.3 |        6.92x
   65536 |      21039.5 |       2619.7 |        8.03x
```

## Validation

- `cargo check -j 1 -p frankenlibc-abi --test conformance_diff_wcsrchr`: passed
  via RCH on `vmi1227854`.
- Strict clippy for the same test was blocked by unrelated pre-existing
  `frankenlibc-core` lints in `exp.rs`, `sort.rs`, `fnmatch.rs`, and `regex.rs`.
- The live worktree also contains unstaged `wcsspn` changes; those are excluded
  from this closeout.

## Verdict

Kept. Score = `(Impact 5 * Confidence 4) / Effort 2 = 10.0`.
