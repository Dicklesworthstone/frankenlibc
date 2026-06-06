# bd-2g7oyh.178: memcmp_4096 broadword equality probe rejected

## Target

- Bead: `bd-2g7oyh.178`
- Fresh profile source: clean `main` after `bd-2g7oyh.177` closeout.
- RCH baseline worker: `ts1`
- Baseline command: `cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_(memcpy_4096|memmove_4096|memset_4096|memchr_absent|memcmp_4096)' --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3`
- Baseline target row: `glibc_baseline_memcmp_4096`
- Baseline numbers: FrankenLibC p50 `60.216 ns`, mean `66.786 ns`; host glibc p50 `37.952 ns`, mean `42.387 ns`.

## Lever

One structural probe shape only: replace the 128-byte `memcmp` equal-block SIMD-mask fold with a broadword XOR/OR equality probe over sixteen 8-byte chunks. The ordered mismatch resolver was left unchanged.

This intentionally did not retry exact-size certificate widening, 512-byte folded blocks, wider portable-SIMD panels, or rank-select first-difference extraction.

## Behavior proof

- RCH proof worker: `vmi1264463`
- Proof command: `cargo test -p frankenlibc-core memcmp -- --nocapture --test-threads=1`
- Result: passed 29 focused unit/property tests plus `string_properties::golden_memcmp_corpus_sha256` and `string_properties::prop_memcpy_then_memcmp_is_zero`.
- Golden memcmp sha256: `23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e`

## Isomorphism

- Compared prefix length stayed `n.min(a.len()).min(b.len())`.
- Equal-block predicate was still exact: XOR/OR reports no difference iff every byte in the 128-byte block is equal.
- For any non-equal block, control still used the existing 32-byte panel resolver and byte-wise `compare_bytes`, preserving first differing byte ordering and tie-breaking.
- No floating-point or RNG behavior exists in this path.

## Post-benchmark

Same-worker post benchmark on `ts1`:

- Candidate broadword probe: p50 `85.750 ns`, mean `85.066 ns`
- Baseline SIMD folded probe: p50 `60.216 ns`, mean `66.786 ns`

The candidate regressed the primary row by `42.4%` p50 and `27.4%` mean. Score is below the keep gate.

## Decision

Rejected and source restored for the `memcmp` lever. The next `memcmp` attack should use a different algorithmic shape, not safe broadword chunk extraction via `u64_from_chunk`; that extraction cost dominated the equal-buffer path.
