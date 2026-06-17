# bd-5rf9xk pass183 strcpy4096 certified scan-copy keep

Date: 2026-06-17
Agent: BoldFalcon
Mode: local fallback, `RCH_REQUIRE_REMOTE=0` because `ts1`/remote RCH is offline
Commit base: `d290c2fdc` (`chore(perf): reject memchr mask-fold pass181`)

Note: this artifact filename was created before remote pass182 routing
(`bd-2g7oyh.465`) landed. The progress log records this kept source pass as
pass183 after rebasing on top of that routing pass.

## Target

After pass181 rejected the `memchr_absent` explicit mask-fold source lever,
`strcpy_4096` was the next material residual from the pushed routing evidence.
Focused local Criterion reproduced it on current head:

| impl | Criterion interval | p50 | mean |
| --- | ---: | ---: | ---: |
| FrankenLibC baseline | `[68.010 ns 69.444 ns 70.904 ns]` | `66.589 ns` | `72.609 ns` |
| host glibc | `[46.879 ns 47.806 ns 48.741 ns]` | `48.701 ns` | `50.398 ns` |

Baseline log SHA-256:

`54b94946e1c2ba4b643e71b8da194f9d7b201502460b5d814a913edbc04a3a2f`

## Lever

Route the exact 4097-byte `strcpy` path through the existing certified
512-byte scan-copy helper instead of `strlen(src) + 1` followed by a separate
prefix copy.

For each 512-byte data block, the helper loads eight 64-byte SIMD panels,
certifies that the block is NUL-free, and only then writes that block to the
destination. If a block contains a NUL, the path falls back to
`copy_strcpy_terminal_from` for that block, preserving destination tail bytes
after the first NUL. If all eight data blocks are NUL-free, the final byte is
the known terminator at index 4096.

This is distinct from the old eight-block NUL-certificate/full-copy family: the
copy is committed block-by-block only after each block is proven NUL-free,
instead of running a whole-source scan and then a second whole-source copy.

## Post Benchmark

| impl | Criterion interval | p50 | mean |
| --- | ---: | ---: | ---: |
| FrankenLibC post | `[53.026 ns 55.576 ns 58.461 ns]` | `52.739 ns` | `56.405 ns` |
| host glibc | `[45.794 ns 46.625 ns 47.624 ns]` | `44.986 ns` | `50.910 ns` |

Post log SHA-256:

`a834979f443031d760b240c8cbde39287c8f8be58de4143735545e1fc24d4f1b`

Improvement vs focused FrankenLibC baseline:

- p50: `66.589 -> 52.739 ns` (`1.263x`)
- mean: `72.609 -> 56.405 ns` (`1.287x`)

Score: `8.0` (`Impact 9.0 x Confidence 0.89 / Effort 1.0`). Keep threshold
`>= 2.0` cleared.

## Behavior Proof

Isomorphism:

- First-NUL ordering is preserved by per-block certification plus the existing
  `copy_strcpy_terminal_from` resolver for the first block containing NUL.
- Copied byte order is unchanged.
- Return count remains the inclusive-NUL byte count.
- Destination tail after an early NUL remains untouched: NUL-containing blocks
  are not pre-written before the exact prefix resolver runs.
- The all-data-NUL-free case writes exactly bytes `0..4096` from source and
  then the known terminator at byte `4096`.
- Panic behavior, overlap policy, allocation state, errno, locale, FP state,
  and RNG state are unchanged.
- Existing strcpy golden transcript SHA-256 remains
  `fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401`.

Validation:

| command | result | log SHA-256 |
| --- | --- | --- |
| `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs` | pass | n/a |
| `git diff --check` | pass | n/a |
| `cargo check -j 1 -p frankenlibc-core --lib` | pass with existing iconv warnings | `1cdc56d9b57f026bee31ef6b15091fc921488dc60e045d4eb356fe85e6127597` |
| `cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1` | pass, `7 passed` | `8b29d868dfb52023bb7eba8d82c0718a99f56d534f8b7afe4eb961816762c22a` |
| `cargo fmt -p frankenlibc-core --check` | attempted, blocked by unrelated existing formatting drift in `ether`/`float128` | `68d6ccc7e485164bc6d50f35ff7241f51a4971848c185e518c46cfae6af58854` |
| `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings` | attempted, blocked by unrelated existing `iconv`/`resolv` lint debt | `3a8194f6e60f4c91a126ed7a7a8517fef795239414789dfa8af67797dd599e5c` |

## Next Route

Reprofile current head. Do not return to `strcpy_4096` with old
whole-source NUL-certificate/full-copy, SWAR certificate, global certificate,
terminal split, exact dispatch-hoist, array-copy lowering, wrapper inlining,
typed exact lowering, or this certified 512-byte scan-copy lever.
