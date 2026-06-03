# bd-2g7oyh.57 wmemrchr 16-lane reverse panels

## Target

`crates/frankenlibc-core/src/string/wide.rs::wmemrchr`.

After `bd-2g7oyh.56`, allocator and byte-string `strlen` were still owned by
peer agents. A fresh RCH profile on unowned wide-string benches showed
`wmemrchr_absent_4096` as the slowest untouched wide path.

## Baseline

RCH profile command before edit:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wmemchr_absent|wmemrchr_absent|wcslen|wcschr_absent|wcsrchr_absent|wcsstr_absent|wmemcmp_equal' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Worker: `vmi1156319`.

Focused baseline rows:

| bench | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `wmemrchr_absent_16` | 5.176 | 20.000 | 6793.000 | 148.117 |
| `wmemrchr_absent_64` | 11.891 | 30.000 | 220.000 | 17.676 |
| `wmemrchr_absent_256` | 39.291 | 55.000 | 260.000 | 44.996 |
| `wmemrchr_absent_1024` | 148.105 | 222.164 | 390.000 | 158.319 |
| `wmemrchr_absent_4096` | 626.653 | 935.500 | 961.500 | 655.181 |

## Alien Primitive

Primitive: vectorized execution / blocked reverse equality kernel amortization.

The prior reverse scan filtered equality eight `u32` lanes at a time from the
back of the bounded prefix. This lever widens only `wmemrchr`'s reverse filter
to sixteen lanes, then preserves the unchanged scalar right-to-left resolver in
the first rear-most candidate panel.

## Implementation

- Added `WIDE_REVERSE_SIMD_LANES = 16`.
- Switched only `wmemrchr` chunking and `Simd<u32, _>` construction from
  `WIDE_SIMD_LANES` to `WIDE_REVERSE_SIMD_LANES`.
- Left `wmemchr`, `wcslen`, `wcschr`, `wcsrchr`, `wcsstr`, and `wmemcmp`
  untouched.

## Isomorphism Proof

- `count = n.min(s.len())` is unchanged, so the searched prefix is identical.
- `rchunks_exact(16)` partitions the same suffix-aligned prefix into larger
  rear-to-front clean panels; a clean 16-lane skip is equivalent to two clean
  8-lane skips for the exact predicate `x == c`.
- The first rear-most candidate panel still resolves right-to-left with the
  unchanged scalar `chunk[j] == c` loop, preserving rightmost-match
  tie-breaking.
- Remainder handling is unchanged except the front remainder is modulo 16
  instead of modulo 8; it still scans `(0..end).rev()` over the exact remaining
  prefix.
- No-match behavior remains `None` after all panels and the front remainder are
  exhausted.
- Floating-point and RNG behavior are not involved.

## Post Benchmark

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench wmemrchr_absent -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Worker: `vmi1293453`. `rch exec` did not expose a worker pin; this post worker
differed from the baseline worker, so the keep decision records that caveat.

| bench | pre p50 | post p50 | pre mean | post mean | p50 speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| `wmemrchr_absent_16` | 5.176 | 1.999 | 148.117 | 6.770 | 2.59x |
| `wmemrchr_absent_64` | 11.891 | 3.795 | 17.676 | 10.294 | 3.13x |
| `wmemrchr_absent_256` | 39.291 | 10.621 | 44.996 | 18.980 | 3.70x |
| `wmemrchr_absent_1024` | 148.105 | 35.234 | 158.319 | 38.332 | 4.20x |
| `wmemrchr_absent_4096` | 626.653 | 170.250 | 655.181 | 177.458 | 3.68x |

Target `wmemrchr_absent_4096` improved on p50, p95, p99, and mean. Every size
improved materially on p50.

Score: `(Impact 3.0 * Confidence 2.5) / Effort 1.0 = 7.5`, keep.

## Validation

- Pre source hash: `e107ee4df8c5390b9ed14f84899814ba3de469b8a4fbc7913421eb71f5712c8d`.
- Post source hash: `0812c45a421b6ccc67bc75436db80861051a93c731a145b67a43d520636e5d5f`.
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
  blocked by unrelated existing lints in
  `crates/frankenlibc-core/src/malloc/allocator.rs:72`, `:78`, and
  `crates/frankenlibc-core/src/stdlib/sort.rs:1000`; no `wide.rs` lint was
  reported before the external failure.
- `cargo fmt --check`: blocked by unrelated peer-dirty formatting in
  `crates/frankenlibc-abi/tests/conformance_diff_mb_utf8_rfc2279.rs`,
  `crates/frankenlibc-core/src/stdlib/sort.rs`,
  `crates/frankenlibc-core/src/string/mem.rs`, and several
  `crates/frankenlibc-harness/tests/*` files.
