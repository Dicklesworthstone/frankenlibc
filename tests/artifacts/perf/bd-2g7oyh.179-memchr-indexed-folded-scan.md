# bd-2g7oyh.179: memchr_absent indexed folded scan

## Target

- Bead: `bd-2g7oyh.179`
- Profile-backed hotspot: `glibc_baseline_memchr_absent`
- Baseline worker: `vmi1149989`
- Baseline command:
  `RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass3-memory-profile cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_(memcmp_4096|memchr_absent|memmove_4096|memcpy_4096|memset_4096|strcpy_4096|strrchr_absent|strchr_absent|strlen_4096)' --noplot --sample-size 35 --warm-up-time 1 --measurement-time 3`
- Baseline row: FrankenLibC p50 `28.465 ns`, mean `31.508 ns`; host glibc p50 `19.634 ns`, mean `21.556 ns`.

## Lever

Replace `memchr`'s `chunks_exact` iterator state machine with an indexed folded-block scan:

- Keep the existing safe portable-SIMD 256-byte folded absent-heavy predicate.
- Keep the existing 32-byte first-byte resolver for matching panels.
- Keep the existing exact SWAR word tail and scalar byte tail.
- Change only hot-loop control flow from iterator/remainder state to explicit monotonically-increasing offsets.

This is the alien-graveyard/vectorized-execution primitive applied at the libc memory-scan level: remove tuple/iterator state around a vectorized scan and keep the hot loop as a compact indexed kernel.

## Behavior proof

- Formatting:
  `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`
- Whitespace:
  `git diff --check`
- RCH proof command:
  `RCH_WORKER=vmi1149989 RCH_PREFERRED_WORKER=vmi1149989 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-179-proof FRANKENLIBC_PROPTEST_CASES=4096 cargo test -p frankenlibc-core memchr -- --nocapture --test-threads=1`
- Proof result: passed 10 focused `memchr`/`wmemchr` lib tests plus property tests.
- Golden-output verification: `string_properties::golden_memchr_corpus_sha256` passed.
- Check:
  `RCH_WORKER=vmi1149989 RCH_PREFERRED_WORKER=vmi1149989 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-179-check cargo check -p frankenlibc-core --all-targets`
  passed.
- Clippy:
  `cargo clippy -p frankenlibc-core --all-targets -- -D warnings` was attempted through RCH and failed on unrelated/peer-owned code: `crates/frankenlibc-core/src/math/exp.rs` excessive precision and dirty `crates/frankenlibc-core/src/stdio/file.rs` unwrap-after-is_some diagnostics. No `mem.rs` diagnostics were reported before the unrelated failure stopped the crate.

## Isomorphism

- `count = n.min(haystack.len())` is unchanged.
- The folded 256-byte predicate is unchanged and remains an existence test only.
- If a folded block contains the needle, panels are resolved in increasing address order and `first_byte_simd_32` returns the lowest matching lane. This preserves first-occurrence ordering.
- Tail handling is unchanged semantically: 32-byte panels, then exact 8-byte SWAR probes, then scalar byte remainder.
- Offset progression is monotonic and non-overlapping. `while count - base >= WIDTH` avoids overflow while covering exactly the same prefix as the iterator form.
- No floating-point, RNG, tie-breaking, locale, errno, or allocation behavior exists in this path.

## Same-worker benchmark

Post command:
`RCH_WORKER=vmi1149989 RCH_PREFERRED_WORKER=vmi1149989 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-179-post cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_(memchr_absent|memcmp_4096|memmove_4096|memcpy_4096|memset_4096)' --noplot --sample-size 35 --warm-up-time 1 --measurement-time 3`

Worker: `vmi1149989`

Primary row:

- Baseline FrankenLibC: p50 `28.465 ns`, mean `31.508 ns`
- Post FrankenLibC: p50 `20.916 ns`, mean `22.816 ns`
- Delta: p50 `26.52%` faster, mean `27.59%` faster
- Post host glibc: p50 `21.097 ns`, mean `22.005 ns`

Guard rows were noisy across full Criterion invocations and are treated as context only. The accepted code touches only `memchr`; the primary same-worker delta is large and directionally consistent.

## Decision

Accepted.

Score: `(Impact 5 * Confidence 5) / Effort 2 = 12.5`

Next profile pass should not retry `memchr` panel-width changes. If memory scans remain dominant, target a different structural primitive such as shared forward/reverse scan layout, ABI-layer scan/copy specialization, or allocator/bin data-structure work after a fresh profile.
