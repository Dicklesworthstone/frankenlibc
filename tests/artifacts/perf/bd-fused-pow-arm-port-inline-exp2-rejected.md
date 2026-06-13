# Fused-pow with INLINE exp2 minimax — REJECTED (perf), 2026-06-13

## What was tried (the previously-untried attack)
Prior fused-pow rejections (bd-e4jb7k) all kept `libm::exp2` as an external call.
The remaining hypothesis was: a *fully* fused single routine with an INLINE exp2
minimax (no `libm::exp2`, no `libm::log2` calls) would eliminate the
call/finalization overhead and beat glibc. This session implemented exactly that:

- `log2_kernel_hilo(x) -> (hi, lo)`: the existing `log2_kernel` with its already-
  internal `(hi, lo)` decomposition exposed (fast-two-sum renormalized), so the
  exponent multiply happens in double-double.
- `exp2_dd_inline(wh, wl)`: inline `2^(wh+wl)` — integer split + a degree-12
  minimax (Taylor) polynomial for `2^r` on `[-0.5, 0.5]` (12 FMAs) + `scalbn`.
- pow medium path: `(lh,ll)=log2_kernel_hilo(base); wh=y*lh; wl=fma(y,lh,-wh)+y*ll;
  exp2_dd_inline(wh,wl)` — no libm exp2/log2 calls.

## Result
- ACCURACY: PASS. The 1M-point `pow_medium_log2_exp2_fast_path_large_sweep`
  4-ULP-vs-glibc gate stayed green. So 4-ULP accuracy IS achievable this way —
  this is new information (prior dd-lite attempts were perf-rejected, not measured
  for the inline-exp2 accuracy).
- PERF: FAIL, 2.3-3.0x SLOWER than glibc for generic medium exponents:
  pow(x,2.1)=3.01x, pow(x,-2.3)=2.33x, pow(x,0.7)=2.38x (vs glibc, x in [0.5,2.5)).
  (pow(x,1.5)=0.58x is misleading — half-integer hits a different fast path.)
  The inline degree-12 exp2 minimax + the log2 64-entry-table kernel + the dd
  arithmetic is HEAVIER than glibc's hand-tuned fused-asm pow, not lighter.

## Conclusion (4th rejection — lever confirmed dead in safe Rust)
Eliminating the libm calls does NOT help; the cost is the arithmetic itself. No
safe-Rust composition (table-log2 + polynomial-exp2 + dd) beats glibc's tuned-asm
pow — the gap is fundamental to glibc's autotuned register-blocked asm tables.
The ONLY conceivable path is transcribing glibc/ARM-optimized-routines pow.c's
EXACT 128-entry `__pow_log_data` + `exp_data` tables verbatim (not available in-
tree; home-grown coeffs already proven insufficient). EV is low (1.9x on a cold
profile) and risk/effort is high. Recommend leaving pow on the current
`libm::exp2(exponent*libm::log2(base))` medium path. Reverted cleanly; no code
shipped.
