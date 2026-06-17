# bd-2g7oyh.467 pass185 memset4096 fill rejection

Date: 2026-06-17T10:44:00Z

Head for focused baseline/post: `e477fde5e chore(perf): route current head pass 184`

Current integration head after restore: `86e96b9fc fix(math): correct f128 ABI for frexpf128 + tidy fminf128 (bd-9z5ikz batch 4)`

Reason: pass184 local routing selected `memset_4096` as the next tractable non-fresh string target after larger rows were fresh no-repeat lanes. `ts1` is offline, so this pass used local `rch` with `RCH_REQUIRE_REMOTE=0` and crate-scoped target directories.

## Baseline

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass185-baseline-target-20260617T1027 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memset_4096 --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Log: `target/perf-logs/bd-2g7oyh-pass185-memset-baseline.log`

Log SHA-256: `efe7e76fabb485e9cc4af522bf80ec94d7253f78f638853147fff474dc85490c`

Rows:

| Impl | p50 ns/op | mean ns/op | Criterion interval |
| --- | ---: | ---: | --- |
| FrankenLibC | `31.253` | `34.771` | `[32.601 ns 33.498 ns 34.399 ns]` |
| host glibc | `30.919` | `33.083` | `[31.341 ns 31.899 ns 32.511 ns]` |

## Lever Tested

Replace the manual byte loop in `crates/frankenlibc-core/src/string/mem.rs::memset`:

```rust
for byte in &mut dest[..count] {
    *byte = value;
}
```

with Rust's slice fill lowering:

```rust
dest[..count].fill(value);
```

This was one source lever only. It preserves the same `count = n.min(dest.len())` clamp, the same byte value, and the same prefix-only mutation boundary.

## Behavior Proof

Focused proof command:

```bash
env CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass185-proof-target-20260617T1030 \
  cargo test -j 1 -p frankenlibc-core memset -- --nocapture
```

Log: `target/perf-logs/bd-2g7oyh-pass185-memset-tests.log`

Log SHA-256: `5e5f4b6160c07657297e1a8f14f75e645be7cfb804854830607fa606a19b6e86`

Direct results:

- `string::mem::tests::test_memset_basic`: passed
- `string::mem::tests::test_memset_partial`: passed
- `string::mem::tests::prop_memset_only_mutates_requested_prefix`: passed
- `string_properties::prop_memset_fills_prefix`: passed
- `string::wide::tests::test_wmemset_basic`: passed
- `string::wide::tests::prop_wmemset_overwrites_prefix_only`: passed

Isomorphism:

- Ordering/tie-breaking: unchanged; `memset` has no ordering decision.
- Floating point: unchanged; no FP code or rounding state touched.
- RNG: unchanged; no RNG use.
- Allocation/errno/locale state: unchanged; no allocation, errno, or locale path touched.
- Golden-output reference: Criterion row continues to reference `tests/conformance/fixtures/string_memory_full`; focused property tests prove prefix mutation and suffix preservation.

## Post Benchmark

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass185-post-target-20260617T1032 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memset_4096 --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Log: `target/perf-logs/bd-2g7oyh-pass185-memset-post.log`

Log SHA-256: `222dc79be5f108482e8ece538bc09ab5fcc2681512912486dbdeae526cbdf68c`

Rows:

| Impl | p50 ns/op | mean ns/op | Criterion interval |
| --- | ---: | ---: | --- |
| FrankenLibC candidate | `30.987` | `34.234` | `[32.544 ns 33.254 ns 33.919 ns]` |
| host glibc | `35.806` | `36.924` | `[36.273 ns 37.059 ns 37.859 ns]` |

The candidate moved FrankenLibC only `31.253 -> 30.987 ns` p50 and `34.771 -> 34.234 ns` mean. The Criterion intervals overlap the baseline, and the absolute change is sub-nanosecond, so this is not a real enough win for the Score gate.

## Restore Proof

The source was restored manually after rejection.

```bash
sha256sum crates/frankenlibc-core/src/string/mem.rs
```

Restored source SHA-256: `78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d`

`git diff -- crates/frankenlibc-core/src/string/mem.rs` is empty after restore.

## Verdict

REJECTED. Score `0.0`: tiny/noisy sub-nanosecond movement with overlapping Criterion intervals. Do not retry the `slice::fill`/library-lowering surface lever for `memset_4096`.

Next route: reprofile current head after this rejection. If `memset_4096` remains material, require a fundamentally different primitive such as a safe exact-size array store/copy-shape or backend codegen artifact, not another loop-to-library lowering.
