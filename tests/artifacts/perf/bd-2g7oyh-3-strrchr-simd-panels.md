# bd-2g7oyh.3 strrchr safe-SIMD reverse panels

## Target

- Bead: `bd-2g7oyh.3`
- Commit: `5c13048b40adaeefaef4a970336610a348c296a7`
- Function: `find_last_byte_before` in `crates/frankenlibc-core/src/string/str.rs`
- Profile-backed symptom: `strrchr_absent` large-buffer reverse scans still used 8-byte SWAR panels after `strlen`, while forward string scans already used 32-byte safe SIMD panels.

## Alien Primitive Card

- Primitive: contiguous SIMD group probing, analogous to Swiss-table control-byte probes, applied directly to byte-string panels.
- Lever: one safe-Rust `std::simd::Simd<u8, 32>` equality probe per reverse panel, then scalar right-to-left resolution only inside candidate panels.
- EV: `(Impact 3 * Confidence 4 * Reuse 2) / (Effort 1 * Friction 1) = 24.0`.
- Fallback: revert on existing-test hash mismatch, changed NUL-bound/last-match semantics, or p50 regression at 1024B/4096B.

## Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- strrchr_absent --sample-size 50 --noplot
```

Fresh pre-change baseline on `vmi1153651`:

| Case | p50 ns/op | p95 ns/op | p99 ns/op |
|---|---:|---:|---:|
| `strrchr_absent_16` | 14.097 | 30.000 | 55.000 |
| `strrchr_absent_64` | 23.466 | 33.877 | 95.500 |
| `strrchr_absent_256` | 71.126 | 110.308 | 171.883 |
| `strrchr_absent_1024` | 282.046 | 471.254 | 620.130 |
| `strrchr_absent_4096` | 1041.234 | 1508.464 | 1552.736 |

Commit-recorded same-campaign baseline:

| Case | p50 ns/op |
|---|---:|
| `strrchr_absent_16` | 11.657 |
| `strrchr_absent_64` | 21.310 |
| `strrchr_absent_256` | 64.062 |
| `strrchr_absent_1024` | 245.286 |
| `strrchr_absent_4096` | 935.374 |

## Behavior Proof

Pre-change command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core 'string::str::tests::' --lib -- --nocapture --test-threads=1
```

Pre-change result: 102/102 `string::str::tests::` passed.

Existing-test transcript hash:

```text
2525355f145b2beeb284d482bdd4928750f0094baf9c319f473daed8ae5ae7dc
```

Post-change result: 104/104 `string::str::tests::` passed, including:

- `test_strrchr_simd_panel_resolves_last_match_before_terminator`
- `test_strrchr_simd_panel_ignores_match_after_terminator`

Existing-test transcript hash after excluding only the two new tests:

```text
2525355f145b2beeb284d482bdd4928750f0094baf9c319f473daed8ae5ae7dc
```

Full post transcript hash from the independent confirmation run:

```text
469b3b692472989205af3d422a89ddc8457bf474e470cbaa7eef6a22b99ef1c2
```

Commit-recorded full post transcript hash:

```text
235e4da93b185ebe3f01964dd290d33f97b492e083f8bd5e4fbc39208023a507
```

Isomorphism:

- Ordering preserved: yes. `strrchr` still computes `strlen(s)` first, then scans only bytes before that bound.
- Tie-breaking preserved: yes. SIMD is used only as a membership probe; matching panels are resolved with the same scalar right-to-left search, so the last byte before the terminator still wins.
- Floating-point: N/A. The path uses integer byte comparisons only.
- RNG: N/A. No random state or runtime controller state is touched.
- Error classes: unchanged. Public return remains `Some(index)` or `None`; `c == 0` still returns `Some(strlen(s))` before the helper.

## Post Benchmark

Same command as baseline.

Independent confirmation run on `vmi1149989`:

| Case | p50 ns/op | p95 ns/op | p99 ns/op |
|---|---:|---:|---:|
| `strrchr_absent_16` | 5.965 | 12.517 | 20.000 |
| `strrchr_absent_64` | 14.192 | 30.000 | 36.925 |
| `strrchr_absent_256` | 28.857 | 65.528 | 100.000 |
| `strrchr_absent_1024` | 119.584 | 203.004 | 290.778 |
| `strrchr_absent_4096` | 442.991 | 880.904 | 995.988 |

Commit-recorded post run on `vmi1149989`:

| Case | p50 ns/op |
|---|---:|
| `strrchr_absent_16` | 8.606 |
| `strrchr_absent_64` | 13.398 |
| `strrchr_absent_256` | 32.036 |
| `strrchr_absent_1024` | 145.570 |
| `strrchr_absent_4096` | 390.288 |

## Score

- Independent p50 speedup: `1024B 282.046 -> 119.584 ns` (2.36x), `4096B 1041.234 -> 442.991 ns` (2.35x).
- Commit-recorded p50 speedup: `1024B 245.286 -> 145.570 ns` (1.68x), `4096B 935.374 -> 390.288 ns` (2.40x).
- Keep score: `Impact 4 * Confidence 4 / Effort 1 = 16.0`.

## Validation

All validation passed:

- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core 'string::str::tests::' --lib -- --nocapture --test-threads=1`
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets`
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings`
- `TMPDIR=/data/tmp cargo fmt --check -p frankenlibc-core`
- `git diff --check`
