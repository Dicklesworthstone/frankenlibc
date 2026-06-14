# bd-o8s0sj dtoa stack-format closeout

Target: `[perf] alloc-free byte-identical float dtoa for ecvt/fcvt/gcvt/qcvt`

## Baseline

- Independent focused RCH baseline captured by BoldFalcon on `vmi1153651` before the pushed keep commits:
  - `glibc_baseline_gcvt/gcvt_multi/frankenlibc_core`: p50/mean `12538.509/15768.339 ns`
  - `glibc_baseline_gcvt/gcvt_multi/host_glibc`: p50/mean `1749.081/1848.901 ns`

## Kept Source Commits

- `ece101ec1` `perf(gcvt): render floats into a stack buffer, drop the per-call format! heap alloc`
  - Commit evidence: `gcvt` moved from `1.72x` slower than glibc to `0.97-1.04x` vs glibc.
  - Proof: `conformance_gcvt_byte_stable` golden SHA `9f2591...` over specials plus `100432` random double x ndigit cases.
- `bc879761` `perf(ecvt/fcvt): render floats into a stack buffer, drop per-call format! heap String`
  - Commit evidence: `ecvt` moved from `1.47x` slower than glibc to `0.97x`; `fcvt` at parity.
  - Proof: `conformance_ecvt_byte_stable` golden SHA `f9f43c...` over specials plus `80365` random double x ndigit cases.

## Isomorphism

- Same Rust float formatting machinery and same precision arguments are used.
- Only the output sink changed from heap `String` allocation to `StackStr`, a fixed stack-backed `core::fmt::Write` buffer with heap fallback on overflow.
- Ordering, rounding, trailing-zero trimming, exponent normalization, sign handling, FP special cases, and the known `bd-2g7oyh.101` ecvt policy are unchanged.

## Validation

- Recorded by source commits: `conformance_diff_cvt_specials`, stdlib numeric differential tests, strfromd/strfromf differential fuzz, core ecvt unit tests, and the byte-stable golden tests passed.
- RCH post rerun from this pane was blocked by fleet pressure (`critical_pressure=2`, remote required refused local fallback); accepted post evidence is the already-pushed keep commit proof.

Verdict: KEPT. Score >= 2.0.
