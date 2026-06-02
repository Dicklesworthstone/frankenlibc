# runtime_math control kernels — pass 4 (frankenlibc-membrane)

Worker: rch AMD EPYC (kernels_bench self-pins via taskset), bench profile, criterion --sample-size 50.
Directly relevant to the (now-fixed) validate hotspot bd-tti4cb: these kernels are what the heavy
`validate_with_security_context` + `observe_validation_result` path pays for. The bd-tti4cb fix
(4729bfba) bypasses them for null/cached/empty-oracle fast exits (validate_null 3095->10ns), but a
genuine full-validate (e.g. validate_foreign_nonempty_oracle, residual 1091ns) still pays them.

## Composite paths (runtime_math_bench, strict)
| path | p50 | note |
|------|-----|------|
| decide | 98.9 ns | RuntimeMathKernel decision alone |
| decide_observe | 981.8 ns | decide + feedback |
| **observe_fast** | **1953.0 ns** | `observe_validation_result` feedback update — the dominant full-path cost |

## Per-kernel ranked (runtime_math_kernels_bench, strict)
| Rank | kernel | p50 ns | p95 ns | note |
|------|--------|--------|--------|------|
| 1 | **design_choose_plan** | **1008.7** | 1131.7 | OptimalDesignController D-optimal scheduler — dominates |
| 2 | sos_barrier_quarantine_eval | 264.1 | 331.7 | SOS barrier certificate, quarantine polynomial |
| 3 | sos_barrier_fragmentation_eval | 49.3 | 67.3 | SOS barrier, fragmentation |
| 4 | sos_barrier_size_class_eval_with_lookup | 15.5 | 18.7 | |
| 5 | approachability_observe | 10.4 | 15.0 | |
| 6 | pareto_recommend_profile | 10.0 | 13.1 | |
| 7 | approachability_summary | 4.5 | 5.7 | |
| 8 | barrier_admissible | 1.0 | 3.8 | constant-time guard ✓ |
| 9 | bandit_select_profile | 0.52 | 1.9 | ✓ |
| 10 | sos_barrier_provenance_eval | 0.31 | 2.5 | ✓ |
| 11 | risk_upper_bound_ppm | 0.31 | 1.9 | ✓ |

## Hypothesis ledger
```
H-design  design_choose_plan recomputes a full logdet (Cholesky + 4 ln) per candidate probe : SUPPORTS (PRIMARY)
  design.rs:204-208 — inside the `for probe in Probe::ALL` loop it does
  `let mut trial = self.fisher; rank_one_update(&mut trial, ...); logdet_spd(&trial)`.
  logdet_spd (design.rs:287) is a 4x4 Cholesky followed by 4 `.ln()` calls. With ~base + COUNT
  candidates that is ~10 log-determinants (~40 ln) per call (LATENT_DIM=4) => ~1009ns.
  FIX: matrix-determinant lemma — logdet(A + w·vvᵀ) = logdet(A) + ln(1 + w·vᵀA⁻¹v). Maintain A⁻¹
  (or its Cholesky factor) once per call (O(d³)), then each candidate gain is a single ln of a
  quadratic form (O(d²), one ln). Cuts ~40 ln -> ~1 inverse + COUNT ln. Bead: bd-wvxyzs.

H-sos-quarantine  sos_barrier_quarantine_eval ~264ns is the #2 kernel : SUPPORTS (secondary)
  ~5x the other sos_barrier variants (fragmentation 49ns, size_class 15ns, provenance 0.31ns).
  Likely a larger SOS polynomial / more monomials in the quarantine certificate. Bead (P3): bd-wvxyzs.

H-observe-dominates  the feedback path, not decide, is the cost : SUPPORTS
  decide 99ns vs observe_fast 1953ns. design_choose_plan (1009) + sos_quarantine (264) + other
  per-observe updates account for most of observe_fast. Confirms the bd-tti4cb root cause and shows
  the residual full-validate cost is concentrated in design_choose_plan.
```

## Filed beads
- **** (P2, perf/runtime-math) — design_choose_plan 1009ns; matrix-determinant-lemma fix.
- **bd-x9lb9g** (P3, perf/runtime-math) — sos_barrier_quarantine_eval 264ns (#2 kernel).
- **bd-wvxyzs** (P2, perf/runtime-math) — design_choose_plan 1009ns; matrix-determinant-lemma fix.
