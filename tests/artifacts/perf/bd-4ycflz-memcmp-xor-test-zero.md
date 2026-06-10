# bd-4ycflz memcmp XOR/test-zero folded predicate

Date: 2026-06-10
Agent: BoldFalcon
Scope: `crates/frankenlibc-core/src/string/mem.rs`

## Target

`bd-4ycflz` targeted `glibc_baseline_memcmp_4096`, equal 4096-byte buffers.
The broad profile basis was FrankenLibC p50 `51.172 ns`, mean `59.393 ns`
vs host p50 `41.780 ns`, mean `56.114 ns` on `vmi1227854`.

Prior rejected families: folded-panel widening, broadword probes, 64-lane
rank-select masks, exact-size branchbacks, inline-only visibility, and manual
copy-panel analogues. This pass uses only the remaining codegen-shaped lever:
replace the 128-byte folded inequality predicate with XOR/OR accumulation and
one zero comparison.

## Focused Baseline

Command:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd4ycflz-baseline-j1-target \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memcmp_4096 --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`.

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 55.705 | 77.218 | 95.096 | 423.045 |
| host glibc | 39.459 | 42.774 | 53.086 | 85.301 |

## Change

```text
before: (a0.simd_ne(b0) | a1.simd_ne(b1) | a2.simd_ne(b2) | a3.simd_ne(b3)).any()
after:  ((a0 ^ b0) | (a1 ^ b1) | (a2 ^ b2) | (a3 ^ b3)).simd_ne(0).any()
```

The scan shape stays 128 bytes. The first-difference result still comes from
the existing 32-byte panel scan and byte resolver.

## Proof

Commands:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 rch exec -- env \
AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
cargo test -j 1 -p frankenlibc-core --lib memcmp -- --nocapture --test-threads=1
```

Result: passed 31 tests covering core memcmp, timingsafe memcmp, wmemcmp, and
`memcmp_golden_output_sha256`.

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 rch exec -- env \
AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
cargo test -j 1 -p frankenlibc-core --test property_tests \
golden_memcmp_corpus_sha256 -- --nocapture --test-threads=1
```

Result: passed.

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
```

Result: passed.

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 rch exec -- env \
AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
cargo check -j 1 -p frankenlibc-core --lib
```

Result: passed.

Strict RCH clippy was attempted with:

```text
cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings
```

Result: failed on existing unrelated lint debt outside this change:
`math/exp.rs` excessive precision, `stdlib/sort.rs` collapsible-if,
`string/fnmatch.rs` type-complexity/collapsible-if, and
`string/regex.rs` collapsible-if/unnecessary-map-or. No lint was reported in
`string/mem.rs`. A follow-up run with those known groups allowed was refused by
RCH capacity with `remote required; refusing local fallback`.

Known unrelated warning during RCH builds: missing SMT solver for the generated
stdio proof artifact.

## Same-worker Post

Command:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd4ycflz-candidate-j1-target \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memcmp_4096 --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`.

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 48.915 | 53.418 | 57.500 | 80.000 |
| host glibc | 43.962 | 45.867 | 50.770 | 67.450 |

Primary delta: FrankenLibC p50 `55.705 -> 48.915 ns` (`12.2%` faster);
mean `77.218 -> 53.418 ns` (`30.8%` faster). The FL/host p50 ratio improved
from `1.41x` slower to `1.11x` slower.

## Isomorphism

- Ordering preserved: yes. The changed predicate only decides whether a
  128-byte block contains any difference.
- Tie-breaking unchanged: yes. The first differing byte is still resolved by
  the existing ordered 32-byte panel and byte scan.
- Floating-point: N/A.
- RNG: N/A.
- Golden outputs: `memcmp_golden_output_sha256` and
  `golden_memcmp_corpus_sha256` passed.

## Score

Impact `4` x Confidence `4` / Effort `1` = `16.0`.

Verdict: keep.
