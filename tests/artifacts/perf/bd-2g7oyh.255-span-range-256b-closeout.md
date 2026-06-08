# bd-2g7oyh.255 span_range 256B folded block closeout

## Target

Profile-backed target: `strspn`/`strcspn`/`strpbrk` contiguous-range spans in
`crates/frankenlibc-core/src/string/str.rs`.

Code commit already pushed to `origin/main` and `origin/master`:
`95f5e7ffa5a9555f394124730f532081539383e2`.

## Baseline and Post

The shipped commit records the same Criterion workload family and p50 results:

| Workload | Baseline FL p50 | Post FL p50 | Host p50 in post context | Result |
| --- | ---: | ---: | ---: | --- |
| `glibc_baseline_strspn_long` | 505.76 ns | 58.53 ns | 330 ns | 8.64x faster than baseline |
| `glibc_baseline_strpbrk_absent` | 591.38 ns | 188.08 ns | 295 ns | 3.14x faster than baseline |

Score: `(Impact 5 * Confidence 5) / Effort 1 = 25.0`.

## Lever

One source lever: fold eight native 32-byte SIMD panels into one 256-byte
contiguous-range stop test. This amortizes horizontal reductions while keeping
the exact scalar `table` scan for any flagged block.

## Isomorphism Proof

- Ordering preserved: yes. Folded SIMD only skips blocks proven to have no stop;
  any flagged block is scanned left-to-right with the original membership table.
- Tie-breaking unchanged: yes. If a NUL and member/non-member stop are in the
  same block, scalar resolution returns the earliest byte exactly as before.
- Floating-point: N/A.
- RNG: deterministic proof corpus uses a fixed LCG seed only for test data.
- Golden output: `span_range_matches_scalar_reference_and_golden` pins digest
  `9462047517241184641` over strspn/strcspn/strpbrk results across contiguous
  and non-contiguous sets, 256-byte boundaries, stops at varied offsets, and NUL
  handling.

## Validation

- RCH `vmi1156319`: `cargo test -p frankenlibc-core span_range -- --nocapture --test-threads=1` passed.
- The first closeout proof exposed one warning in the proof test (`unused_mut`);
  closeout commit removes it without changing the optimized path or golden corpus.
