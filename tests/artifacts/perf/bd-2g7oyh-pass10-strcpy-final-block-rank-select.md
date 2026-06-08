# bd-2g7oyh.246: strcpy_4096 final-block rank-select rejection

## Target

Fresh post-`a06bdd9a` RCH profile on `vmi1149989` selected
`glibc_baseline_strcpy_4096` as the largest current p50 residual:

| row | FrankenLibC p50 | FrankenLibC mean | host p50 | host mean |
|---|---:|---:|---:|---:|
| `strcpy_4096` broad profile | 84.511 ns | 89.824 ns | 51.250 ns | 57.077 ns |

Focused same-worker baseline on `vmi1149989`:

| row | FrankenLibC p50 | FrankenLibC mean | host p50 | host mean |
|---|---:|---:|---:|---:|
| `strcpy_4096` | 60.490 ns | 61.768 ns | 34.951 ns | 37.643 ns |
| `strlen_4096` guard | 23.936 ns | 27.103 ns | 19.606 ns | 24.848 ns |
| `memcpy_4096` guard | 42.128 ns | 47.378 ns | 39.438 ns | 41.753 ns |

## Lever

Candidate one-lever change in `crates/frankenlibc-core/src/string/str.rs`:
after the existing `block_has_nul_512` detector found a terminator in the final
512-byte block, resolve the first NUL with a 64-lane SIMD bitmask and
`trailing_zeros`, then copy the resolved prefix with one slice copy.

This deliberately did not retry the prior `bd-2g7oyh.144` fused scan/store
block layout.

## Behavior Proof

RCH `vmi1149989` proof command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd246-strcpy-proof \
  RUST_TEST_THREADS=1 \
  cargo test -p frankenlibc-core strcpy -- --nocapture --test-threads=1
```

Result: passed 5/5 `strcpy` tests, including
`test_strcpy_golden_transcript_sha256`, the no-NUL panic contract, and the
trailing-destination untouched guard.

Isomorphism obligations were satisfied by construction and test:

- First-NUL ordering: the low set bit in the SIMD NUL mask is the first NUL
  lane in panel order; panels were checked left-to-right.
- Writes: only bytes through the first NUL were copied; bytes after the NUL
  remained untouched.
- Panic/fallback contract: no-NUL and too-small destination paths used the
  unchanged fallback path.
- Floating-point and RNG: not involved.

## Post-Benchmark

Same-worker post on `vmi1149989`:

| row | baseline FL p50 | baseline FL mean | post FL p50 | post FL mean |
|---|---:|---:|---:|---:|
| `strcpy_4096` | 60.490 ns | 61.768 ns | 95.000 ns | 111.822 ns |
| `strlen_4096` guard | 23.936 ns | 27.103 ns | 31.913 ns | 34.384 ns |
| `memcpy_4096` guard | 42.128 ns | 47.378 ns | 40.967 ns | 41.473 ns |

Verdict: rejected and source restored. Score `0.0`.

Next route: do not retry final-block rank-select or the earlier fused
scan/store family. The next `strcpy_4096` attack should replace the overall
algorithmic shape, for example an unrolled two-stream copy-plus-NUL detector
that copies and accumulates NUL masks in the same 64-byte panels with a
bounded write contract, or route to a different profile-backed residual if the
fresh profile shifts.
