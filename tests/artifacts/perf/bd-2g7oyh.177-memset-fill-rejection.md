# bd-2g7oyh.177: memset_4096 slice-fill lowering rejected

## Target

- Bead: `bd-2g7oyh.177`
- Profile-backed hotspot: `glibc_baseline_memset_4096`
- Baseline evidence from bead creation on `vmi1227854`: FrankenLibC p50 `20.713 ns`, mean `23.151 ns`; host glibc p50 `17.687 ns`, mean `19.988 ns`.
- Single lever tested: replace the manual `for byte in &mut dest[..count] { *byte = value; }` loop in `frankenlibc_core::string::mem::memset` with `dest[..count].fill(value)`.

## Behavior proof

- RCH proof command:
  `RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-177-proof RUST_TEST_THREADS=1 cargo test -p frankenlibc-core memset -- --nocapture --test-threads=1`
- Worker selected: `vmi1149989`
- Result: passed focused `memset` unit/property tests and the candidate golden corpus test.
- Candidate golden sha256: `691185abfee9bb74b79a2e393c91c460ba7df94c1273068b4c9bdd98a71b6797`

## Isomorphism

- `count = n.min(dest.len())` is unchanged.
- Both forms write exactly `value` into `dest[..count]` and leave `dest[count..]` untouched.
- The mutable slice borrow prevents observable aliasing during the fill; no ordering, tie-breaking, floating-point, or RNG behavior exists in this path.
- Returned count and final buffer are identical for all tested empty, partial, full, overlong, and 4096-byte cases.

## RCH same-worker benchmark

Worker: `ts1`

Criterion estimates from clean baseline worktree `/data/projects/.scratch/frankenlibc-bd-2g7oyh-177-baseline-5259cf63` at `5259cf63`:

- Baseline manual loop: median `37.266 ns`, mean `37.216 ns`
- Candidate `slice::fill`: median `37.094 ns`, mean `37.320 ns`

The candidate median improvement was only `0.46%`, while the mean regressed by `0.28%`. This does not meet the Score >= 2.0 keep gate.

## Decision

Rejected and restored source. Next structural primitive should target the larger residuals still visible in the same memory profile, especially safe-Rust SWAR/shuffle scans for `memchr_absent`/`memcmp_4096` or allocator structural work, not further memset loop lowering.
