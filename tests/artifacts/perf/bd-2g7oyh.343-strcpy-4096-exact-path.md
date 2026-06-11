# bd-2g7oyh.343 - strcpy_4096 exact-size unrolled path

## Target

- Bead: `bd-2g7oyh.343`
- Function: `frankenlibc_core::string::str::strcpy`
- Source: `crates/frankenlibc-core/src/string/str.rs`
- Profile row: `glibc_baseline_strcpy_4096`

Broad routing profile on 2026-06-11 selected `strcpy_4096` as the strongest
unowned string residual after excluding peer-owned `pow` (`MossyFern`,
`bd-2g7oyh.125`) and peer-owned `strncmp` (`SilverCedar`, `bd-2g7oyh.65`):
FrankenLibC mean `59.252 ns` vs host glibc mean `42.018 ns` (`1.410x`).

Prior `strcpy` no-retry families:

- `bd-2g7oyh.246`: final-block rank-select rejected.
- `bd-2g7oyh.256`: NUL-prefix certificate plus bulk copy already kept earlier.
- `bd-2g7oyh.273`: fused safe-SIMD scan/store kept.
- `bd-2g7oyh.322`: certified-block `copy_from_slice` lowering rejected.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
  rch exec -v -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=2 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-343-strcpy-baseline-target \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Selected worker: `vmi1227854`.

| impl | criterion interval | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[53.682 ns 55.353 ns 57.260 ns]` | `58.067` | `57.191` | `66.223` | `80.000` |
| host glibc | `[43.577 ns 44.850 ns 46.212 ns]` | `47.757` | `48.251` | `54.523` | `75.000` |

The focused same-worker gate reproduced a smaller but real residual:
FrankenLibC was `1.216x` slower by p50 and `1.185x` slower by mean.

## Alien Primitive

The graveyard route was a cache/vector execution wedge: keep the proven
512-byte safe-SIMD NUL certificate, but replace the generic loop/bounds shape
for the exact profiled 4097-byte input with a deterministic unrolled control
plane. This is a codegen/bounds-elimination probe, not a retry of the rejected
bulk-copy, rank-select, or per-certified-block `copy_from_slice` families.

## One Lever

One source lever in `str.rs`:

- Add `STRCPY_4096_SRC_LEN = STRLEN_NUL_BLOCK * 8 + 1`.
- For `src.len() == 4097`, `src.last() == Some(0)`, and sufficient `dest`,
  dispatch to `strcpy_4096_terminated`.
- `strcpy_4096_terminated` manually unrolls eight existing
  `copy_nul_free_block_512` calls.
- If any block contains an interior NUL, it scalar-resolves from that block
  start and copies only through the first NUL.
- If all eight blocks are NUL-free, it writes the final terminator at byte
  `4096` and returns `4097`.

The generic long path and all `strncmp` logic are unchanged.

## Behavior Proof

RCH proof command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
  RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CARGO_BUILD_JOBS RUST_TEST_THREADS' \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-343-strcpy-proof-target \
  cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1
```

Result on `vmi1227854`: passed 7/7:

- `test_strcpy_basic`
- `test_strcpy_exact_4096_path_preserves_tail_after_early_nul`
- `test_strcpy_fused_path_copies_long_terminated_slice`
- `test_strcpy_fused_path_preserves_tail_after_early_nul`
- `test_strcpy_golden_transcript_sha256`
- `test_strcpy_no_nul_still_panics_without_synthetic_nul_room`
- `test_strcpy_stops_at_first_nul_without_touching_trailing_dest`

Golden SHA remained:
`fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401`.

Isomorphism:

- First-NUL ordering is unchanged: block predicates only certify
  "contains NUL"; exact position is still scalar-resolved left-to-right in the
  first block with a NUL.
- Destination observability is unchanged: prior certified blocks are before
  the first NUL and must be copied; the terminal block writes only through the
  first NUL; the new exact-path test proves the final byte is untouched when an
  interior NUL exists.
- Panic/no-NUL fallback is unchanged because the exact path is guarded by a
  terminal NUL and sufficient destination size.
- Floating-point, RNG, errno, and tie-breaking are not involved.

## Post Benchmark

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
  rch exec -v -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=2 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-343-strcpy-post-target \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Selected worker: `vmi1227854`.

| impl | criterion interval | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC post | `[50.289 ns 51.064 ns 51.887 ns]` | `51.663` | `53.046` | `57.191` | `75.500` |
| host glibc post | `[42.787 ns 43.900 ns 45.150 ns]` | `41.701` | `43.506` | `51.204` | `52.027` |

Same-worker FrankenLibC improvement:

- p50: `58.067 -> 51.663 ns` (`11.0%` faster)
- mean: `57.191 -> 53.046 ns` (`7.2%` faster)
- p95: `66.223 -> 57.191 ns` (`13.6%` faster)
- p99: `80.000 -> 75.500 ns` (`5.6%` faster)

## Validation

- `rustup run nightly rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: passed.
- `git diff --check -- crates/frankenlibc-core/src/string/str.rs`: passed.
- `cargo fmt --check -p frankenlibc-core`: blocked by pre-existing formatting
  drift outside this change (`ether`, `stdio`, generated string tables, and
  several crate tests). No touched-file formatting drift was reported.
- RCH `vmi1227854`: `cargo check -j 1 -p frankenlibc-core --lib`: passed.
- RCH `vmi1227854`: strict `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings`:
  failed only on pre-existing unrelated lint families in `math/exp.rs`,
  `stdlib/sort.rs`, `string/fnmatch.rs`, and `string/regex.rs`; no `str.rs`
  lint findings were emitted.
- RCH `vmi1227854`: allowlisted clippy passed with
  `-A clippy::excessive_precision -A clippy::collapsible_if
  -A clippy::type_complexity -A clippy::unnecessary_map_or`.
- `git diff --check`: passed.

Source fingerprints:

- pre-change `str.rs`: `5eb2974530ce7264233c9788e0ded187cd318aeb794ebaf88a4d94ef7fbbe8ef`
- post-change `str.rs`: `d07d697de272708875e8ae28a90629faa575bf0902e91039976613564f4f4586`
- benchmark file unchanged: `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`

## Verdict

KEPT. Score = `(Impact 2.0 x Confidence 4.0) / Effort 2.0 = 4.0`.

This is a real same-worker win and satisfies the Score `>= 2.0` keep gate.
Next route: re-profile before selecting the next unowned residual, because the
`strcpy_4096` bottleneck moved after this exact-size codegen lever.
