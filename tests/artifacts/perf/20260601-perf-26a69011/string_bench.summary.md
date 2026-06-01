# string_bench — frankenlibc-core::string hot-kernel pass

Worker: rch (AMD EPYC), bench profile, criterion --sample-size 40 --measurement-time 2. 81 records, 16 functions, mode=raw. p50 ns/op by haystack size; needle/char absent (full scan).

| function | 16 | 64 | 256 | 1024 | 4096 | ns/byte@4096 | class |
|----------|----|----|-----|------|------|--------------|-------|
| memcpy | 2.4 | 2.6 | 3.1 | 11.4 | 31.6 | **0.0077** | SIMD (copy_from_slice) ✓ |
| strcmp | 3.7 | 7.9 | 28.4 | 94.8 | 351.8 | 0.086 | scalar, ok |
| strlen | 3.3 | 7.3 | 30.1 | 113.1 | 432.7 | 0.106 | scalar scan |
| memcmp | 8.5 | 30.7 | 111.2 | 393.6 | **1255.3** | **0.306** | **scalar byte loop — 40× memcpy/byte, 3.6× strcmp** |
| strchr_absent | 5.8 | 25.7 | 129.2 | 469.8 | 1496.0 | 0.365 | scalar byte scan |
| strchrnul_absent | 7.2 | 30.3 | 135.9 | 387.2 | 1562.2 | 0.381 | scalar |
| strnstr_bounded | 10.1 | 26.2 | 136.0 | 420.5 | 1721.9 | 0.420 | naive O(n·m) |
| strstr_absent | 12.1 | 32.5 | 140.1 | 499.0 | 1762.2 | 0.430 | naive O(n·m) |
| wcsrchr_absent | 9.0 | 34.6 | 175.3 | 532.7 | 2212.3 | — | wide reverse scan |
| strrchr_absent | 8.8 | 32.2 | 161.3 | 593.7 | 2538.6 | 0.620 | reverse byte scan |
| strspn_full | 13.2 | 47.1 | 238.8 | 1051.7 | 2568.6 | 0.627 | scalar (size-1 set arm) |
| strpbrk_absent | 17.9 | 52.0 | 215.8 | 1007.1 | 2595.3 | 0.634 | scalar (size-1 set arm) |
| strcasestr_absent | 16.4 | 56.9 | 204.7 | 787.2 | 2680.4 | — | case-fold naive |
| wcsstr_absent | 9.4 | 29.1 | 164.4 | 755.4 | 2966.7 | — | wide naive |
| strsep_absent | 13.7 | 43.5 | 192.1 | 887.7 | 3224.7 | — | scalar |
| strcspn_absent | 20.4 | 61.3 | 309.0 | 1071.5 | **3938.5** | 0.961 | scalar (size-1 set arm) |

## Findings / hypothesis ledger
```
H-memcmp  memcmp is a scalar byte-at-a-time loop : SUPPORTS (PRIMARY, bench-evidenced)
  mem.rs:54 — `while i<count { if a[i]!=b[i] ... }`. memcpy (copy_from_slice → SIMD)
  does the same linear traversal at 0.0077 ns/byte; memcmp at 0.306 ns/byte = ~40×.
  strcmp (NUL-terminated, can't bulk-load) is 3.6× FASTER than memcmp despite similar work.
  Fix: word-at-a-time (load usize chunks, compare, byte-resolve the differing word) or
  leverage a vectorizable equality fast-path. Bead: bd-<filed>.

H-byte-scan  strchr/strrchr/strchrnul are scalar byte scans not using memchr/SIMD : SUPPORTS (secondary)
  0.37–0.62 ns/byte vs memcpy 0.0077. memchr in mem.rs uses iter().position() (autovectorizes);
  the str.rs char-scan entrypoints apparently don't route through it. Candidate, lower confidence
  (autovectorization may already help; needs flamegraph/asm confirmation).

H-setmembership-Onm  strcspn/strspn/strpbrk general arm (set len ≥4) is O(n·m) : SUPPORTS-BY-CODE, NOT-MEASURED
  str.rs:~547 general arm does `reject_set.contains(&byte)` (linear set scan) per haystack byte.
  glibc builds a 256-entry bitset once → O(n+m). BUT the current bench uses a 1-char set
  (reject=b"Z\0") so it hits the special-cased size-1 scalar arm, NOT this path. The 3938ns@4096
  is the scalar size-1 scan, not O(n·m). Latent algorithmic issue; needs a ≥4-char-set bench to
  measure. Bead (P3): bd-<filed>.

H-substr-naive  strstr/strnstr/strcasestr are naive O(n·m) (str.rs:317) not Two-Way : SUPPORTS-BY-CODE
  glibc uses Two-Way O(n+m). The "absent, rare-first-char" bench keeps naive ~linear, so worst
  case (frequent first-char, near-misses) is NOT measured here. Noted; not filed (no adversarial bench).
```

## Cross-pass note
memcpy is the only kernel that is properly vectorized. The recurring theme across frankenlibc-core::string is **scalar byte loops where word/SIMD or table-driven algorithms are standard** — memcmp is the clearest, bench-evidenced instance.

## Filed beads (optimizer hand-off)
- **bd-6ypsli** (P2, perf/string) — memcmp scalar byte loop, 1255ns/4096B (~40× memcpy/byte). Bench-evidenced. Fix: word/SIMD compare.
- **bd-yj1zlr** (P3, perf/string) — strcspn/strspn/strpbrk general arm O(n·m) set.contains/byte. Code-confirmed, UNMEASURED (bench uses 1-char set); add ≥4-char-set bench + 256-bitset.
