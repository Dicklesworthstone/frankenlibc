# bd-2g7oyh.53 wide needle/NUL mask fusion

## Target

`crates/frankenlibc-core/src/string/wide.rs::has_wide_or_nul_simd`, used by
the non-NUL `wcschr`, `wcsrchr`, `wcsstr`, and shared first-wide-char/NUL panel
scan paths.

The ready perf queue had no unclaimed child bead after `bd-2g7oyh.52`.
Allocator work was owned by MossyFern (`bd-2g7oyh.51`) and `str.rs` strlen was
owned by BlackThrush (`bd-2g7oyh.25`), so this pass selected an unowned
profile-backed wide-string residual.

## Profile Evidence

Broad RCH profile after commit `f20b5b6b`:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wcschr_absent|wmemchr_absent|wmemrchr_absent|wmemcmp_equal|wcslen|wcsrchr_absent|memchr_absent|memcmp' -- --sample-size 20
```

Worker: `vmi1293453`.

Key residual rows:

| bench | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `wcsrchr_absent_4096` | 329.443 | 363.663 | 581.000 | 322.967 |
| `wcschr_absent_4096` | 297.016 | 325.500 | 661.000 | 296.945 |
| `wmemcmp_equal_4096` | 332.122 | 454.282 | 511.372 | 308.048 |

Focused pre-edit baseline:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wcschr_absent|wcsrchr_absent' -- --sample-size 30 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker: `vmi1149989`.

| bench | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `wcsrchr_absent_16` | 5.352 | 15.000 | 40.662 | 7.872 |
| `wcsrchr_absent_64` | 10.933 | 24.133 | 37.649 | 12.991 |
| `wcsrchr_absent_256` | 32.607 | 51.949 | 80.000 | 34.714 |
| `wcsrchr_absent_1024` | 140.000 | 227.983 | 254.964 | 138.036 |
| `wcsrchr_absent_4096` | 519.661 | 1064.231 | 3817.469 | 615.794 |
| `wcschr_absent_16` | 5.340 | 8.983 | 35.000 | 7.263 |
| `wcschr_absent_64` | 8.110 | 20.000 | 25.500 | 10.685 |
| `wcschr_absent_256` | 26.204 | 49.745 | 60.555 | 30.197 |
| `wcschr_absent_1024` | 87.385 | 159.271 | 212.037 | 94.177 |
| `wcschr_absent_4096` | 395.661 | 744.911 | 1047.392 | 428.287 |

`rch exec` did not expose a worker pin in help, so the post run landed on a
different worker. The post run still used the identical focused command and
showed a coherent full-size curve improvement.

## Alien Primitive

Graveyard primitive: vectorized execution / SIMD control-plane panel scans,
grounded in `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` entries
for vectorized execution and SIMD metadata probing.

Implementation lever: replace two horizontal mask reductions:

```rust
zero_mask.any() || needle_mask.any()
```

with one fused mask reduction:

```rust
(zero_mask | needle_mask).any()
```

The exact scalar candidate resolver is unchanged.

## Isomorphism Proof

- Boolean identity: for each lane, `(lane == 0) OR (lane == needle)` is exactly
  the same predicate as the prior short-circuit expression. Fusing the masks
  changes only when the horizontal reduction is performed, not which panels are
  candidates.
- `needle != 0` remains a precondition of `find_wide_or_nul`, so the two masks
  remain semantically distinct but safely unionable.
- `wcschr`: the first candidate panel is still resolved left-to-right; first
  match ordering and NUL-before-match termination are unchanged.
- `wcsrchr`: skipped panels are still exactly those with no `needle` and no
  NUL; candidate panels are still resolved left-to-right to update `last` until
  NUL terminates. Last-match tie-breaking is unchanged.
- `wcsstr`: first-wide-char candidate discovery still returns the first
  first-character-or-NUL position. Full-needle scalar verification and
  candidate resume order are unchanged.
- `c == 0` paths for `wcschr` and `wcsrchr` do not use this helper and are
  untouched.
- Floating-point and RNG behavior are not involved.

## Post Benchmark

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wcschr_absent|wcsrchr_absent' -- --sample-size 30 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker: `vmi1227854`.

| bench | pre p50 | post p50 | pre mean | post mean | p50 speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| `wcsrchr_absent_16` | 5.352 | 4.522 | 7.872 | 6.398 | 1.18x |
| `wcsrchr_absent_64` | 10.933 | 8.376 | 12.991 | 9.772 | 1.31x |
| `wcsrchr_absent_256` | 32.607 | 23.245 | 34.714 | 26.753 | 1.40x |
| `wcsrchr_absent_1024` | 140.000 | 84.895 | 138.036 | 82.749 | 1.65x |
| `wcsrchr_absent_4096` | 519.661 | 321.156 | 615.794 | 324.705 | 1.62x |
| `wcschr_absent_16` | 5.340 | 3.126 | 7.263 | 5.357 | 1.71x |
| `wcschr_absent_64` | 8.110 | 5.606 | 10.685 | 10.666 | 1.45x |
| `wcschr_absent_256` | 26.204 | 19.408 | 30.197 | 22.271 | 1.35x |
| `wcschr_absent_1024` | 87.385 | 62.938 | 94.177 | 65.647 | 1.39x |
| `wcschr_absent_4096` | 395.661 | 217.404 | 428.287 | 225.386 | 1.82x |

Score: `(Impact 2.0 * Confidence 3.0) / Effort 1.0 = 6.0`, keep.

## Validation

- Pre source hash: `af447fb8724562acad04c76ba5ca5c82fa272cf1899159e0d3edc2d5e630371a`.
- Post source hash: `b82f2feb8929df40630579ab6a3f50ceecfbda8d044c95c2174a7052e7f0535f`.
- `cd tests/conformance/golden && sha256sum -c sha256sums.txt`: passed before
  and after the edit.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs`:
  passed.
- `git diff --check -- crates/frankenlibc-core/src/string/wide.rs`: passed.
- `AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core string::wide::tests:: -- --nocapture`:
  passed, 73/73 wide tests.
- `AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets`:
  passed.
- `AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings`:
  blocked by unrelated existing `clippy::cmp_owned` in
  `crates/frankenlibc-core/src/malloc/allocator.rs:72` and `:78`; no `wide.rs`
  lint was reported before the external failure.
- `cargo fmt --check`: blocked by unrelated dirty formatting in peer-touched
  files, including `crates/frankenlibc-core/src/string/mem.rs` and several
  `crates/frankenlibc-harness/tests/*` files; touched `wide.rs` passed direct
  rustfmt.
