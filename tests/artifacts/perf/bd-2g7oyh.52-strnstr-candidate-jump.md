# bd-2g7oyh.52 strnstr bounded absent scan candidate jump

## Profile target

- Bead: `bd-2g7oyh.52`
- Target: `crates/frankenlibc-core/src/string/str.rs::strnstr`
- Scenario: bounded absent scan with `needle = b"ZQ\0"` over all-`A` haystacks, bound set to the benchmark size.
- Baseline source: fresh RCH `string_bench` profile recorded in the bead on 2026-06-03.
- Baseline worker: `vmi1293453`

## Baseline p50

| Bench | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `strnstr_bounded_absent_4096` | 1544.609 | 1795.470 | 1863.875 | 1559.088 |

Sibling context from the same profile: `strstr_absent_4096=74.858 ns`, `strcasestr_absent_4096=101.678 ns`, `strsep_absent_4096=80.582 ns`.

## Alien primitive

Canonical source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` section 7.7, Swiss Tables SIMD group probes, plus the no-gaps directive for safe-Rust SIMD string/memory scans.

Recommendation card:

- Primitive: packed first-byte-or-NUL control-plane scan, adapted from Swiss-table control-byte probing to bounded C-string substring search.
- Runtime artifact: route candidate discovery through existing safe-Rust `find_byte_or_nul(&haystack[start..limit], first)` and keep exact scalar full-needle verification.
- Fallback: return to scalar left-to-right byte stepping if golden hashes change, NUL ordering regresses, or focused p50 fails the keep gate.
- EV score: Impact 5 x Confidence 5 / Effort 1 = 25.0.

## One lever shipped

The bounded scan now jumps directly to the next byte equal to `needle[0]` or to the first NUL within `haystack[start..limit]`. Every candidate still runs the original exact scalar suffix comparison, and false candidates resume at `i + 1`.

No benchmark harnesses, allocator paths, strlen/strstr/strcasestr logic, API signatures, or public error contracts were changed.

## Isomorphism proof

- Ordering preserved: `find_byte_or_nul` returns the earliest first-byte candidate or NUL in the remaining bounded window. False candidates resume from the next byte, so later windows are visited in the same order as the scalar loop.
- Tie-breaking unchanged: the first complete full-needle match still returns immediately; overlapping candidates still resolve from the lowest offset.
- Bound semantics unchanged: `limit = min(n, haystack.len())`; candidates whose suffix cannot fit within `limit` still return `None`, matching the scalar early-exit because no later candidate can fit.
- NUL-before-candidate unchanged: a NUL found before any candidate returns `None`.
- Candidate-before-NUL unchanged: a candidate found before a later NUL is verified exactly before termination can win.
- Unterminated haystack unchanged: if no NUL is present in the bounded region, absent first-byte scans return `None`; present candidates can still match inside the bound.
- Empty needle unchanged: `strlen(needle) == 0` still returns `Some(0)` before the candidate-jump path.
- Floating-point: N/A.
- RNG: N/A.

## Golden behavior proof

- Command: `sha256sum -c sha256sums.txt`
- Workdir: `tests/conformance/golden`
- Result: `fixture_verify_strict_hardened.v1.md: OK`; `fixture_verify_strict_hardened.v1.json: OK`.

## Post benchmark

- Command: `AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 rch exec -- cargo bench -p frankenlibc-bench --bench string_bench strnstr_bounded_absent -- --sample-size 20`
- Worker: `vmi1156319`

| Bench | Baseline p50 ns/op | Post p50 ns/op | Delta |
| --- | ---: | ---: | ---: |
| `strnstr_bounded_absent_16` | n/a | 20.328 | context |
| `strnstr_bounded_absent_64` | n/a | 19.301 | context |
| `strnstr_bounded_absent_256` | n/a | 27.893 | context |
| `strnstr_bounded_absent_1024` | n/a | 52.281 | context |
| `strnstr_bounded_absent_4096` | 1544.609 | 163.557 | 9.45x faster |

Post 4096 full row: `samples=33 p50_ns_op=163.557 p95_ns_op=229.374 p99_ns_op=601.000 mean_ns_op=182.956 throughput_ops_s=5189009.165`.

Gate decision: kept. The profiled 4096 bounded absent scan clears Score>=2.0 by a wide margin.

## Validation

- `AGENT_NAME=BoldFalcon rch exec -- cargo test -p frankenlibc-core string::str::tests::test_strnstr -- --nocapture` passed remotely on `vmi1149989`: 18/18 `strnstr` tests passed.
- `AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 rch exec -- cargo check -p frankenlibc-core --all-targets` passed remotely on `vmi1156319`.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs` passed.
- `git diff --check -- crates/frankenlibc-core/src/string/str.rs` passed.
- Workspace/package fmt note: `cargo fmt --check --package frankenlibc-core` is currently blocked by unrelated existing formatting drift in `crates/frankenlibc-core/src/string/mem.rs`.
- Clippy note: `AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings` is currently blocked by unrelated existing `clippy::cmp_owned` lints in `crates/frankenlibc-core/src/malloc/allocator.rs:72` and `:78`.

## Source

- Pre `str.rs` sha256: `d78b0b75a89d83b803ddd9f9894519d948ca69920ac979d60ae81d306017fcf4`
- Post `str.rs` sha256: `f03437e87f0984886102468786825af6e07e7cb30b25751d2ab651a41bc305fb`
