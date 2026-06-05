# bd-2g7oyh.144 strcpy_4096 fused copy-until-NUL

## Target

- Profile-backed workload: `glibc_baseline_strcpy_4096`
- Broad RCH profile (`vmi1149989`, after bd-2g7oyh.142/.143): FrankenLibC p50 `48.884ns`, host p50 `27.708ns`.
- Focused baseline command:
  `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- strcpy_4096 --sample-size 60 --measurement-time 3 --warm-up-time 1 --noplot`

## Baseline

RCH selected `ts2`.

- FrankenLibC: p50 `100.908ns`, p95 `111.047ns`, p99 `140.025ns`, mean `103.548ns`
- host glibc: p50 `65.435ns`, p95 `67.526ns`, p99 `100.500ns`, mean `67.432ns`

## Lever

One lever in `crates/frankenlibc-core/src/string/str.rs`: add a conservative `strcpy` fast path for source slices that already end in NUL and destinations that can hold the whole source slice. The fast path scans 512-byte safe-SIMD panels for NUL, stores NUL-free panels from loaded vectors, and scalar-resolves only the panel containing the first NUL. All no-NUL, empty, or potentially too-small cases fall back to the previous `strlen` + `copy_from_slice` implementation.

Alien primitive: fused scan/store block layout, replacing separate discover-then-copy passes for the profiled terminated long-copy lane.

## Isomorphism

- Ordering: first NUL remains the sole stop condition. The folded block check only decides whether a block has any NUL; if it does, panels are checked in increasing order and the hit panel is copied scalar byte-by-byte through the first NUL.
- Writes: NUL-free blocks before the first NUL are copied exactly. Bytes after the first NUL are not touched; covered by `test_strcpy_stops_at_first_nul_without_touching_trailing_dest`.
- Panic contract: the fast path is entered only when `src.last() == Some(0)` and `dest.len() >= src.len()`, which implies the old `dest.len() > strlen(src)` assertion would pass. All no-NUL and possibly too-small cases use the old implementation; covered by `test_strcpy_no_nul_still_panics_without_synthetic_nul_room`.
- Return value: returns copied bytes including the terminating NUL, equal to old `strlen(src) + 1`.
- Floating point: N/A.
- RNG: N/A.

## Post-benchmark

Same command as baseline. RCH selected `ts2` again.

- FrankenLibC: p50 `75.630ns`, p95 `82.954ns`, p99 `106.172ns`, mean `78.978ns`
- host glibc: p50 `65.339ns`, p95 `71.431ns`, p99 `85.500ns`, mean `67.420ns`
- Improvement: p50 `100.908ns -> 75.630ns` (`1.33x`), mean `103.548ns -> 78.978ns` (`1.31x`).
- Residual gap to host: p50 `75.630ns / 65.339ns = 1.16x`.
- Score: Impact `3.0` x Confidence `0.90` / Effort `1.0` = `2.70`, keep.

## Proof Commands

- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon cargo test -p frankenlibc-core strcpy -- --nocapture`
  - PASS: `4 passed; 0 failed`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon cargo check -p frankenlibc-core --all-targets`
  - PASS.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`
  - PASS.
- `git diff --check -- crates/frankenlibc-core/src/string/str.rs`
  - PASS.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon cargo clippy -p frankenlibc-core --all-targets -- -D warnings`
  - BLOCKED by pre-existing unrelated lints in `stdio/printf.rs`, `string/regex.rs`, `string/wide.rs`, `stdlib/sort.rs`, `string/fnmatch.rs`, plus older `str.rs` test byte-slice lint. No clippy errors were emitted for the new `strcpy` fast path.

## Golden Hashes

```text
27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89  tests/conformance/fixtures/string_ops.json
94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4  tests/conformance/fixtures/string_memory_full.json
20c73d64d39caa6e175c63e362673354bb9d93e16625658b31225ae4a5da2d98  crates/frankenlibc-core/tests/property_tests.rs
0dd83c1d974c2196527d451600f63902ef6ce54dd263c1e0ee2d42c33f3680a3  crates/frankenlibc-core/src/string/str.rs
```
