# bd-2g7oyh.258 - qsort 128 x i32 natural-order fast lane

Date: 2026-06-08
Agent: BoldFalcon

## Target

Profile-backed residual: `glibc_baseline_qsort_128_i32`.

Pre-edit bead profile on RCH `vmi1153651`:
- FrankenLibC p50 4606.047 ns, mean 4743.301 ns
- host glibc p50 4095.041 ns, mean 4294.265 ns

Fresh pass-12 RCH profile artifact:
- `/data/tmp/frankenlibc-pass12-profile`
- FrankenLibC p50 4448.869 ns, mean 4673.800 ns
- host glibc p50 4491.898 ns, mean 4461.390 ns

Clean detached baseline artifact:
- `/data/tmp/frankenlibc-qsort258-clean-baseline`
- FrankenLibC p50 4620.497 ns, mean 4859.110 ns
- host glibc p50 4444.945 ns, mean 4442.013 ns

## Lever

One source lever in `crates/frankenlibc-core/src/stdlib/sort.rs`:
- for width-4 arrays with 64..=2048 elements, copy native-endian 4-byte elements into `Vec<i32>`;
- sort those keys with Rust's integer `sort_unstable`;
- write the candidate sorted bytes back;
- verify every adjacent pair using the caller's comparator on actual element slices;
- if any adjacent pair is inverted under the comparator, restore the exact original byte elements and fall back to the existing generic pdqsort.

This is an integer-specialized sorting primitive, not another pdqsort partition micro-tune.

## Behavior proof

RCH proof:
- worker: `vmi1156319`
- command: `cargo test -p frankenlibc-core qsort -- --nocapture --test-threads=1`
- result: passed; 9 qsort unit tests plus the qsort property test passed.

Golden artifacts:
- existing qsort FNV corpus stayed `0x9a03_8cb3_bfb2_d40e`
- signed-i32 SHA-256 corpus digest: `deea996e631cd592e8bc3d2b05f8c68d6c08ae8942525079beba773c0d241a75` on little-endian
- fallback/restore test: descending comparator restores original bytes and falls through to generic qsort, producing descending order.

Isomorphism:
- `qsort` is unstable; observable contract is sorted order under `compar` plus input multiset preservation.
- The fast lane commits only after the caller comparator certifies adjacent nondecreasing order over the candidate bytes.
- For natural native-endian `i32` comparators, integer sorting produces the same sorted multiset.
- For non-natural comparators, bytewise/lexicographic comparators, descending comparators, or side-condition comparators that reject the candidate order, original element bytes are restored before generic pdqsort runs.
- Equal-element tie order is unspecified by C `qsort`; the proof pins deterministic output over the golden corpus but does not depend on stability.
- FP/RNG: N/A; all data are integer/byte arrays and deterministic fixed corpora.

## Benchmarks

Candidate confirmation artifact:
- `/data/tmp/frankenlibc-qsort258-candidate`
- FrankenLibC p50 1680.248 ns, mean 1736.477 ns
- host glibc p50 4684.942 ns, mean 4972.071 ns

Focused post RCH bench:
- worker: `vmi1167313`
- artifact: `/data/tmp/frankenlibc-bd258-post-20260608`
- FrankenLibC p50 1497.812 ns, mean 1505.691 ns
- host glibc p50 4536.910 ns, mean 4448.323 ns

Against the bead's original `vmi1153651` profile, the candidate improves p50 from 4606.047 ns to 1680.248 ns, a 2.74x speedup. Against the clean detached baseline artifact, the candidate improves p50 from 4620.497 ns to 1680.248 ns, a 2.75x speedup.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/stdlib/sort.rs` passed.
- RCH `cargo check` / clippy retries were initially refused by worker pressure and active project exclusions; the behavior proof and criterion post bench both built the touched crate successfully.
- Known unrelated warnings observed during RCH bench: missing SMT solver in `stdio_synth` and pre-existing `string/regex.rs` dead-code warning.

## Verdict

KEPT. Score = (Impact 5 * Confidence 4) / Effort 2 = 10.0.

Next route: reprofile after closing because `qsort_128_i32` is now faster than host glibc in the measured row; select the next profile-backed residual rather than tuning the same pdqsort path again.
