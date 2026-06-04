# bd-2g7oyh.25 - strlen 512-byte folded NUL block

Date: 2026-06-04
Agent: BlackThrush

## Target

Profile-backed target: `strlen_4096` residual in `crates/frankenlibc-core/src/string/str.rs`.

One lever kept: add a dedicated 512-byte folded NUL probe for `strlen`, then
fall through to the existing 256-byte folded probe, 64-byte SIMD probe, word
probe, and scalar resolver. The existing 256-byte `STRLEN_BLOCK` helper remains
available for the peer `strspn` single-byte accept fast path.

Graveyard primitive: vectorized execution over byte control planes plus blocked
kernel amortization of horizontal reductions.

## Benchmark

Baseline command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-25-blackthrush-baseline rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- strlen --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Baseline worker: `ts1`

Baseline `STRING_BENCH` rows:

| Bench | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
|---|---:|---:|---:|---:|
| strlen_16 | 3.041 | 12.500 | 60.000 | 5.207 |
| strlen_64 | 3.438 | 10.000 | 171.000 | 7.543 |
| strlen_256 | 5.780 | 12.500 | 481.000 | 16.171 |
| strlen_1024 | 10.646 | 17.500 | 91.000 | 12.231 |
| strlen_4096 | 30.587 | 48.871 | 561.000 | 39.646 |

Post command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-25-blackthrush-postbench rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- strlen --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Post worker: `ts1`

Post `STRING_BENCH` rows:

| Bench | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
|---|---:|---:|---:|---:|
| strlen_16 | 3.840 | 10.000 | 40.000 | 5.027 |
| strlen_64 | 3.387 | 12.500 | 40.000 | 4.898 |
| strlen_256 | 4.815 | 15.000 | 50.000 | 6.965 |
| strlen_1024 | 6.239 | 12.500 | 41.000 | 7.788 |
| strlen_4096 | 28.101 | 33.573 | 370.000 | 36.134 |

Decision metric: `strlen_4096` p50 improved `30.587 -> 28.101 ns/op`
(1.09x), mean improved `39.646 -> 36.134 ns/op` (1.10x), and p95/p99
improved. `strlen_1024` p50 improved `10.646 -> 6.239 ns/op` (1.71x).

Score: Impact 2 * Confidence 4 / Effort 1 = 8.0, kept.

## Isomorphism

- Ordering preserved: yes. The 512-byte and 256-byte folded probes only decide
  whether a block may contain NUL; the existing left-to-right 64-byte, word, and
  scalar resolver still determines the exact first NUL index.
- Tie-breaking unchanged: yes. Multiple NUL bytes in a block still resolve to
  the earliest byte because block probes do not return an index.
- Floating-point: N/A.
- RNG seeds: N/A.
- Unterminated input: unchanged; all clean block probes advance by exact block
  length and the final return remains `s.len()`.
- Hidden bytes after first NUL: unchanged; candidate blocks break before tail
  resolution, so later NULs cannot win over an earlier one.

## Golden Output

Golden fixture checksum before edit:

```text
cd tests/conformance/golden
sha256sum -c sha256sums.txt
fixture_verify_strict_hardened.v1.md: OK
fixture_verify_strict_hardened.v1.json: OK
```

Golden fixture checksum after edit: same command, same OK result.

Final source sha256:

```text
1f85bbb9fed561f7efd4594cf7bd74aa00598eefd70fa0075210b9373512ea1d  crates/frankenlibc-core/src/string/str.rs
```

## Validation

Passed:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs
git diff --check -- crates/frankenlibc-core/src/string/str.rs
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-25-blackthrush-test1b rch exec -- cargo test -p frankenlibc-core string::str::tests::test_strlen -- --nocapture
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-25-blackthrush-prop1c rch exec -- cargo test -p frankenlibc-core --test property_tests prop_strlen -- --nocapture
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-25-blackthrush-check rch exec -- cargo check -p frankenlibc-core --all-targets
```

Results:

- `string::str::tests::test_strlen*`: 4 passed, 0 failed.
- `property_tests prop_strlen`: 1 passed, 0 failed.
- `cargo check -p frankenlibc-core --all-targets`: remote exit 0.

Blocked:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-25-blackthrush-clippy rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings
```

Strict clippy is blocked by unrelated existing lints outside this slice:

- `crates/frankenlibc-core/src/malloc/allocator.rs:72` and `:78`,
  `clippy::cmp_owned` on peer-owned allocator surface.
- `crates/frankenlibc-core/src/stdlib/sort.rs:1000`,
  `clippy::unnecessary_cast` in test corpus setup.

Supplemental clippy with those two lint classes allowed still surfaced unrelated
test-lint backlog in:

- `crates/frankenlibc-core/tests/printf_float_differential_probe.rs`:
  `clippy::approx_constant`.
- `crates/frankenlibc-core/tests/property_tests.rs`:
  `clippy::manual_memcpy` and `clippy::needless_range_loop`.

No clippy diagnostic pointed at `crates/frankenlibc-core/src/string/str.rs`.
