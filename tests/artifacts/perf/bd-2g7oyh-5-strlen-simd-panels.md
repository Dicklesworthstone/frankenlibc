# bd-2g7oyh.5 strlen safe-SIMD forward panels

## Target

- Bead: `bd-2g7oyh.5`
- Function: `strlen` in `crates/frankenlibc-core/src/string/str.rs`
- Profile-backed symptom: after the unaligned prologue, `strlen` still scanned
  8-byte SWAR words for the terminating NUL while sibling `strchr`/`strrchr`
  forward/reverse scans already use 32-byte safe `std::simd` panels.

## Alien Primitive Card

- Primitive: contiguous SIMD group probing, analogous to Swiss-table control-byte
  probes, applied directly to byte-string panels (the byte string is its own
  control plane).
- Lever: one safe-Rust `std::simd::Simd<u8, 32>` NUL-equality probe per 32-byte
  panel before the SWAR word loop; the exact NUL index is still resolved by the
  identical SWAR + scalar tail inside the first candidate panel.
- EV: `(Impact 4 * Confidence 4 * Reuse 2) / (Effort 1 * Friction 1) = 32.0`.
- Fallback: revert on existing-test hash mismatch, any change to first-NUL
  semantics, or p50 regression at 1024B/4096B.

## Baseline

Command:

```text
rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- strlen
```

Fresh pre-change baseline (str.rs strlen lever stashed), same-campaign worker pool:

| Case | p50 ns/op | p95 ns/op | p99 ns/op |
|---|---:|---:|---:|
| `strlen_16` | 5.305 | 7.593 | 55.000 |
| `strlen_64` | 11.911 | 16.228 | 50.500 |
| `strlen_256` | 41.121 | 96.542 | 220.282 |
| `strlen_1024` | 164.438 | 230.500 | 342.603 |
| `strlen_4096` | 515.187 | 665.652 | 807.424 |

## Behavior Proof

Command:

```text
rch exec -- cargo test -p frankenlibc-core --lib string::str
```

Pre-change result: 110/110 `string::str` tests passed.
Post-change result: 112/112 passed, including the two new panel tests:

- `test_strlen_simd_panel_finds_nul_before_hidden_bytes`
- `test_strlen_simd_panel_without_terminator_returns_len`

Existing-test transcript hash (sorted `^test string::str::` lines, excluding the
two new `test_strlen_simd_panel*` tests) is identical before and after the lever:

```text
235e4da93b185ebe3f01964dd290d33f97b492e083f8bd5e4fbc39208023a507
```

Isomorphism:

- Result preserved: `strlen` returns the index of the first `0x00`, else
  `s.len()`. The SIMD panel is a membership-only probe; on a hit the loop breaks
  and the exact index is found by the unchanged SWAR-word and scalar-byte tail.
- Ordering preserved: yes, scan is still strictly left-to-right; the panel only
  fast-skips 32-byte runs proven NUL-free.
- Floating-point: N/A. Integer byte comparisons only.
- RNG: N/A. No random or runtime-controller state touched.
- Error classes: unchanged. No fallible path; pure index return.

## Post Benchmark

Same command as baseline (str.rs strlen lever restored):

| Case | p50 ns/op | p95 ns/op | p99 ns/op |
|---|---:|---:|---:|
| `strlen_16` | 5.548 | 15.270 | 50.000 |
| `strlen_64` | 5.528 | 7.188 | 50.000 |
| `strlen_256` | 11.063 | 15.542 | 60.000 |
| `strlen_1024` | 37.864 | 67.667 | 143.628 |
| `strlen_4096` | 157.133 | 942.350 | 8971.356 |

## Score

- p50 speedup: `64B 11.911 -> 5.528 ns` (2.15x), `256B 41.121 -> 11.063 ns`
  (3.72x), `1024B 164.438 -> 37.864 ns` (4.34x), `4096B 515.187 -> 157.133 ns`
  (3.28x). The 16B case is unchanged (panel never runs below 32B), as expected.
- Improvement scales monotonically with buffer size — the signature of a real
  SIMD scan replacing SWAR, far above the ~25% cross-worker noise floor.
- Keep score: `Impact 4 * Confidence 4 / Effort 1 = 16.0`.

## Validation

All validation passed:

- `rch exec -- cargo test -p frankenlibc-core --lib string::str` (112/112)
- `rch exec -- cargo clippy -p frankenlibc-core --lib -- -D warnings`
- `cargo fmt -p frankenlibc-core --check`
- `git diff --check`
