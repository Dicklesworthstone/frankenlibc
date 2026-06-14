# bd-2g7oyh glibc_baseline_bench full triage (cc)

Date: 2026-06-14
Agent: cc
Status: NO QUALIFYING Score>=2.0 LEVER FOUND (data-backed)

## Method

Ran `cargo bench -p frankenlibc-bench --bench glibc_baseline_bench` (the rigorous
fl-vs-host criterion harness) across the math family, fnmatch, qsort, memmem,
strtoul, scanf rows. p50 ns/op, fl (frankenlibc_core) vs host glibc.

## Result: fl is faster than glibc on ~38 of 40 rows

| row | fl p50 ns | glibc p50 ns | ratio (fl/gl) |
| --- | ---: | ---: | ---: |
| memmem_absent | 37.3 | 17094.6 | 0.002x (glibc pathological absent-case; fl Two-Way) |
| tgamma | 272.7 | 1729.5 | 0.16x |
| fnmatch_adversarial | 21.5 | 90.2 | 0.24x |
| qsort_128_i32 | 879.8 | 2857.1 | 0.31x |
| scanf_hex_long | 29.8 | 91.5 | 0.33x |
| expm1 | 236.6 | 586.3 | 0.40x |
| strtoul_long | 12.4 | 30.4 | 0.41x |
| pow | 377.8 | 858.2 | 0.44x |
| strtoul_hex_long | 12.4 | 28.1 | 0.44x |
| log10f | 162.1 | 361.9 | 0.45x |
| expf_medium | 176.2 | 345.4 | 0.51x |
| log2 | 174.3 | 335.4 | 0.52x |
| log2f | 170.0 | 306.5 | 0.55x |
| pow_half | 453.4 | 799.9 | 0.57x |
| exp2 | 191.6 | 325.8 | 0.59x |
| expm1f | 213.2 | 358.4 | 0.59x |
| exp | 221.4 | 349.7 | 0.63x |
| tanhf | 288.4 | 455.6 | 0.63x |
| cos | 351.3 | 531.9 | 0.66x |
| sin | 366.6 | 556.0 | 0.66x |
| exp_wide | 239.6 | 354.9 | 0.68x |
| atan / cosh / coshf | — | — | 0.76-0.78x |
| powf_int / pow_irrational / sinhf / log10 / erf / lgamma / cbrt / tan / log1p / sinh / tanh | — | — | 0.80-0.92x |
| exp10f / exp10 / log | — | — | 0.89-0.98x |
| **asinh** | 893.3 | 797.5 | **1.12x SLOWER** |
| **powf_irrational** | 441.5 | 380.9 | **1.16x SLOWER** |

## Conclusion

Only two rows are fl-slower, both < 1.2x: asinh (1.12x) and powf_irrational
(1.16x). Closing either to parity is at most a ~1.16x speedup => Score < 2.0, so
NEITHER qualifies as an /extreme-software-optimization lever (a >=2.0 Score needs
a >=2x gap to close). powf_irrational's residue is the documented fused-pow wall
(home-grown coeffs rejected 4x; only a verbatim ARM optimized-routines pow.c
table transcription could beat glibc's asm, EV-low at ~1.9x cold). asinh (libm
delegation) is a 1.12x micro-gap — per the NO-CEILING DIAGNOSIS, a sub-2.0
micro-lever is the WRONG thing to grind.

The only larger gap project-wide is memcpy_4096 (~1.77x, bd-2g7oyh.401) — STILL
< 2.0 and already BoldFalcon's active (NO-CODE REJECTED) lane.

NEXT DEEP LEVER (per reporting rule, NOT a ceiling): the only path to a >=2.0
math win is the verbatim ARM optimized-routines table transcription for the
exp/log/pow family (multi-day, needs the upstream tables in-tree; EV ~1.9x cold).
Everything reachable in safe Rust is already at or past glibc parity.
