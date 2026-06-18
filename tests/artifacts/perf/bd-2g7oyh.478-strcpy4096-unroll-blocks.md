# bd-2g7oyh.478 strcpy4096 exact-block unroll

Date: 2026-06-18
Agent: BlackThrush / cod-b
Status: CODE-FIRST, BATCH TEST PENDING

## Target

Current routing evidence from
`tests/artifacts/perf/bd-2g7oyh-pass190-current-head-after-strlen-routeout-routing.md`
keeps `strcpy_4096` as the largest material residual:

| row | FrankenLibC p50 / mean ns | host p50 / mean ns |
| --- | ---: | ---: |
| `strcpy_4096` | `65.900 / 67.242` | `40.901 / 43.451` |

The same artifact requires focused confirmation before a final keep verdict.
This batch is explicitly code-first: no Criterion, test, or RCH run is executed
now. The only local gate run for this commit is crate-scoped `cargo check`.

## Negative-Evidence Ledger Screen

Already rejected or no-repeat `strcpy_4096` families:

- `strlen(src) + 1` prefix copy repeat.
- Certified 512-byte scan-copy repeat.
- Whole-string scan-then-bulk-copy.
- Global or SWAR NUL certificates.
- Terminal-NUL splitting.
- Dispatch hoists.
- Array-copy lowering.
- Typed exact source/destination lowering.
- Public wrapper inlining.
- Surface loop/tail rearrangement.

This attempt is different: it keeps the retained 512-byte certificate/copy
primitive and changes only the exact-size hot path control graph from a counted
loop to eight straight-line constant-offset calls. The hypothesis is that this
gives LLVM a simpler generated shape for the fixed 4096-byte payload without
changing certificate logic, copy shape, or first-NUL resolution.

## Lever

One source lever in `crates/frankenlibc-core/src/string/str.rs`:

- Add `copy_strcpy_4096_block(dest, src, block_start)`.
- Replace the exact `4096 + NUL` loop in `strcpy_4096_terminated` with eight
  explicit calls at offsets `0, 512, ..., 3584`.
- Preserve the existing ordered resolver for any block whose certificate sees a
  NUL.
- Preserve the terminal-boundary fast path by writing the known final NUL at
  byte `4096` only after all eight payload blocks certify NUL-free.

## Guard

Added `test_strcpy_exact_4096_path_copies_terminal_boundary_payload`:

- Builds an exact `4096 + NUL` source with non-uniform payload bytes.
- Calls `strcpy`.
- Asserts the copied count is exactly `4097`.
- Asserts the copied destination prefix is byte-for-byte equal to the source.
- Asserts bytes after the copied terminator remain untouched.

Existing early-NUL guard remains in place:
`test_strcpy_exact_4096_path_preserves_tail_after_early_nul`.

## Isomorphism

- First-NUL ordering is unchanged: each NUL-positive block calls the existing
  scalar ordered resolver from that block start.
- Copied byte order is unchanged: NUL-free blocks are still copied by
  `copy_nul_free_block_512`.
- Return count is unchanged: early NUL returns `first_nul + 1`; no early NUL
  returns `4097`.
- Destination tail behavior is unchanged: the new guard covers terminal-boundary
  suffix preservation and the existing guard covers early-NUL suffix
  preservation.
- Floating-point, allocation, errno, locale, RNG, and ordering/tie-breaking
  outside the copied bytes are not touched.

## Benchmark Status

Pending by instruction. Required later classification:

- Focused same-worker `glibc_baseline_strcpy_4096` baseline/post Criterion.
- Mark `verified` only if both p50 and mean improve by at least the active keep
  threshold with stable host control.
- Mark `rejected` and revert if p50 or mean regresses, if the Criterion center
  worsens, or if the result is within noise.

Retry-condition predicate: retry this family only after a focused benchmark
proves straight-line codegen is the bottleneck and the emitted IR/assembly
diff shows the loop remained in the previous build. Otherwise do not repeat
exact-block unrolling for `strcpy_4096`.

## Validation

Command run for this batch:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  cargo check -p frankenlibc-core
```

Result: passed.

Existing unrelated warnings:

- `crates/frankenlibc-core/src/iconv/mod.rs:21300`: `emit_g1` does not need
  to be mutable.
- `crates/frankenlibc-core/src/iconv/eucjisx0213_tables.rs:1469`:
  `EUCJX_P2_MULTI` is unused.
