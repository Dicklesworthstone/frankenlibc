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

## Addendum: remaining rows (string/scan/scalar) — completes the full sweep

Measured the rows not in the first pass (p50 ns, fl vs host glibc):

| row | fl | glibc | ratio | note |
| --- | ---: | ---: | ---: | --- |
| strcasestr_absent | 119.0 | 21483.0 | 0.01x | fl crushes glibc's pathological absent-case |
| wcsstr_absent | 318.2 | 2583.2 | 0.12x | |
| scanf_long | 31.0 | 95.1 | 0.33x | |
| strspn_long | 51.5 | 139.3 | 0.37x | |
| strcmp_256_equal | 4.3 | 5.8 | 0.75x | |
| strrchr_absent | 32.4 | 38.1 | 0.85x | |
| strlen_4096 | 19.5 | 21.7 | 0.90x | |
| strchr_absent | 29.6 | 31.8 | 0.93x | |
| strpbrk_absent | 202.1 | 201.4 | 1.00x | |
| strncmp_256_equal | 6.3 | 6.1 | 1.03x | |
| strncasecmp_256_equal | 12.0 | 10.6 | 1.13x | |
| memset_4096 | 41.4 | 35.0 | 1.18x | mem* lane (memset_abi_bench) |
| memchr_absent | 25.6 | 20.0 | 1.28x | |

## Final conclusion (full surface triaged)

Across the ENTIRE glibc_baseline_bench, fl is faster-or-parity on the large
majority; every fl-slower row is sub-1.3x EXCEPT memcpy_4096 (~1.77x, other
agent). Crucially, the slower rows are NOT algorithmic deficiencies — the
algorithms are already maximal: memchr is a 512-bit portable `Simd` x 8-panel
folded scan, strspn/strpbrk use a 256-bit membership bitmap, memmem/strstr are
Two-Way + Boyer-Moore-Horspool, qsort is pdqsort+radix, malloc is segregated +
thread-cache. The residual sub-1.3x gaps (memchr 1.28x, memset 1.18x,
strncasecmp 1.13x, asinh 1.12x, powf_irrational 1.16x) are the irreducible
SAFE-RUST-vs-hand-tuned-asm codegen tax (no prefetch/non-temporal/exact-unroll
control in portable safe Rust), not "the wrong algorithm" — so the NO-CEILING
DIAGNOSIS trigger (a wrong-algorithm streak) does NOT apply. None can yield a
Score>=2.0 lever (max = reach parity, <=1.28x speedup).

NEXT DEEP LEVER (named, not a ceiling): the only >=2.0 path is replacing the
safe-Rust codegen with something the compiler vectorizes to glibc-grade asm —
which for the math family means the multi-day verbatim ARM optimized-routines
exp/log/pow table transcription (EV ~1.9x cold, tables not yet in-tree); for the
mem* scans it is the portable-SIMD wall already being probed (and rejected) by
the mem* lane. No hour-sized safe-Rust lever exists on this surface.
