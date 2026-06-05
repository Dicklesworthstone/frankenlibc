# bd-e4jb7k log2 — hi/lo-lite table prototype findings (SwiftHeron, 2026-06-05)

**Status:** de-risking R&D. NOT shipped (fails the ≤4-ULP-**vs-glibc** conformance
gate by a hair). Materially refines the prior "rejected, dd too slow" verdict.

## TL;DR

The prior rejection (BlackThrush) tried a **full-dd finalization** table log2: it hit
the accuracy but regressed to ~582–628 ns (slower than the 450 ns `ln·LOG2_E` reroute,
never mind glibc's ~318 ns). Conclusion at the time: dd-accumulation log2 is too slow.

This session built the **ARM-optimized-routines-style hi/lo-LITE** finalization instead
(two-sum + one hi/lo split of `1/ln2`, NOT full dd at runtime). Result:

- **Speed: log2_tab ≈ 215–267 ns/batch** vs `libm::log2` 551–746 and the shipped
  `ln·LOG2_E` ~450 — i.e. **~2× faster than libm AND faster than glibc (~318)**.
- **Accuracy: 3 ULP near-1 (1M dense pts), powers-of-two bit-exact, but up to 6 ULP
  vs glibc on the table side.**

## The wall, precisely characterized

At the worst point x = 0.8617554520428125:
```
mine  = -2.14649573809762295173e-1   (~1.9 ULP BELOW true)
true  = -2.14649573809762211907e-1   (dd reference)
glibc = -2.14649573809762128640e-1   (~1.9 ULP ABOVE true)
```
**My prototype is exactly as accurate as glibc — both ~2 ULP off the true value — but
they round in OPPOSITE directions, so mine is ~4–6 ULP FROM glibc.** The ≤4-ULP-**vs-
glibc** contract therefore effectively demands *near-correct-rounding* (≤1 ULP vs true),
because glibc spends ~2 ULP of the budget on its own error. The fast hi/lo-lite path is
genuinely 2-ULP-accurate but cannot meet the *vs-glibc* gate.

ARM optimized-routines `__log2` proves fast **and** ≤1-ULP-vs-true is achievable (~9 ns)
— the missing piece is their **exact degree-6 split-coefficient poly + 128-entry
`__log2_data` table (invc, logc as f64)**, ported VERBATIM. Home-grown Taylor/atanh
coefficients land at ~2 ULP-vs-true; ARM's minimax poly + the way they thread the hi/lo
through the *whole* poly (not just the linear term) is what reaches correct rounding.

## Working recipe (validated structure)

1. **Reduction:** `e = exp(x); m ∈ [1,2)`. Special-case `mant==0 → return e` (powers of
   two bit-exact ✓).
2. **√2 centering to kill the `e+logc` cancellation:** if `m ≥ √2`, use `ek=e+1`,
   `lc = logc-1` (the `-1` is exact by Sterbenz). This alone fixes the catastrophic
   near-1 blowup the prior f64-table hit (461M ULP).
3. **Near-1 branch** for `|x-1| < 0.13`: direct atanh series
   `log2(1+f) = (2/ln2)·atanh(s)`, `s=f/(2+f)`, degree-15 (A1..A15). f=x-1 is exact →
   relative accuracy where the table's absolute error would blow up. **3 ULP on 1M pts.**
4. **Table path** (N=8, 256 buckets): `r = fma(m, invc[i], -1)`,
   `hi/lo finalization`: `w=r·InvLn2hi; (s1,e1)=two_sum(lc,w); (s2,e2)=two_sum(ek,s1);
   result = s2 + (e1+e2 + logc_lo + r·InvLn2lo + r²(C2+r·C3+r·C4+r·C5))`.
5. **Table generation** (offline/once): `logc` MUST be double-double — generate via dd
   `log2` (atanh series, **fma'd t = (v-1)/(v+1)** — the fma on the remainder is
   essential, plain f64 division leaks ~1 ULP), store `(hi,lo)`. InvLn2 split = exact
   ARM constants `0x3FF7154765200000 / 0x3DE705FC2EEFA200`.

## Exact remaining work to ship (est. 1–2 focused hours)

Port ARM optimized-routines `math/log2.c` + `math/log2_data.c` (MIT license) VERBATIM:
the 128-entry `(invc, logc)` table and the degree-6 poly coefficients. That reaches
≤1-ULP-vs-true → passes ≤4-vs-glibc, while staying ~9 ns. Then route the f64 `pow`
medium path (`exp.rs::pow_medium_log2_exp2_fast_path`) through it →
**pow_irrational 34→~15 ns/call, beats glibc** (the prototype already showed tab-medium
pow beating glibc: 552 vs 741 ns/batch). Same table also helps public `log2` (1.26×) and
`log` (1.19×).

## Why this wasn't shipped this turn

A 6-ULP-vs-glibc log2 in the central path would break the existing
`log2_fast_path_within_4_ulps_of_glibc` conformance test AND every downstream pow/tgamma
consumer (high blast radius). The honest gate is the published ARM table+poly, not
home-grown coefficients — that's a bounded follow-up, not an in-the-hour rush.

Prototype lives at `/tmp/tgverify/src/bin/{log2,chk}.rs` (standalone, glibc-FFI validated).
