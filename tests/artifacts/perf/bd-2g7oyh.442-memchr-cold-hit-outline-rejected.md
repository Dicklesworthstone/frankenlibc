# bd-2g7oyh.442 memchr_absent cold-hit outline rejection

Date: 2026-06-16
Agent: BoldFalcon
Status: rejected/restored

## Target

Pass 148 broad RCH routing on `ovh-a` selected
`glibc_baseline_memchr_absent` as the largest clean string residual:

| impl | Criterion interval | p50 ns | mean ns |
| --- | --- | ---: | ---: |
| FrankenLibC broad | `[27.237 ns 27.385 ns 27.580 ns]` | 27.445 | 28.951 |
| host glibc broad | `[17.848 ns 18.106 ns 18.390 ns]` | 18.000 | 19.736 |

Prior no-retry families were active: public-wrapper inlining, exact-4096
dispatch/loop-tail reshaping, slice `contains` absence certificates, panel
width changes, wider folded blocks, indexed folded scans, SWAR word-group
scans, and resolver retuning.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a
RCH_WORKERS=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass149-memchr-baseline-target-20260616T2012
CRITERION_HOME=/data/tmp/frankenlibc-pass149-memchr-baseline-criterion-20260616T2012
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_memchr_absent --noplot --sample-size 80 --warm-up-time 1
--measurement-time 3
```

Focused same-worker result:

| impl | Criterion interval | p50 ns | mean ns |
| --- | --- | ---: | ---: |
| FrankenLibC baseline | `[27.006 ns 27.061 ns 27.122 ns]` | 26.984 | 27.657 |
| host glibc baseline | `[17.895 ns 17.952 ns 18.017 ns]` | 17.902 | 19.251 |

## Candidate

The attempted lever outlined only the rare folded-block hit resolver:

- keep the existing folded SIMD absence predicate unchanged
- keep 256-byte block order unchanged
- keep the 32-byte low-to-high first-match resolver unchanged
- keep 32-byte tail, 8-byte SWAR tail, scalar tail, and clamped `n` unchanged
- move the matching-block resolver into a `#[cold] #[inline(never)]` helper

This was a hot/cold code-layout primitive, not a panel-width or resolver-order
change.

## Behavior Proof

While the candidate was present:

```text
RCH ovh-a cargo test -j 1 -p frankenlibc-core memchr -- --nocapture --test-threads=1
```

Passed the filtered core/lib/property set, including:

- `memchr_golden_output_sha256`
- `golden_memchr_corpus_sha256`
- `prop_memchr_matches_scalar_position`
- `prop_memchr_finds_first_occurrence`
- folded-SIMD first-match boundary tests
- wide `wmemchr` filtered tests

Strict ABI differential also passed:

```text
FRANKENLIBC_MODE=strict cargo test -j 1 -p frankenlibc-abi --test conformance_diff_string diff_memchr_cases -- --nocapture --test-threads=1
```

Isomorphism: first-match ordering, absent-result semantics, bounded `n`,
zero-length handling, pointer-independent core behavior, FP, RNG, allocation,
errno, and locale behavior are unchanged by construction.

## Post Benchmarks

The initial nested-branch cold helper measured as a possible win:

| impl | p50 ns | mean ns |
| --- | ---: | ---: |
| FrankenLibC candidate, nested branch | 20.677 | 21.466 |
| host glibc same run | 18.461 | 19.492 |

But the clippy-suggested let-chain source form was a clear regression:

| impl | p50 ns | mean ns |
| --- | ---: | ---: |
| FrankenLibC candidate, let-chain | 38.735 | 66.264 |
| host glibc same run | 29.748 | 33.269 |

The final allowed nested-branch source shape, with a narrow
`#[allow(clippy::collapsible_if)]`, did not reproduce the win:

| impl | Criterion interval | p50 ns | mean ns |
| --- | --- | ---: | ---: |
| FrankenLibC final candidate | `[29.600 ns 29.741 ns 29.906 ns]` | 29.658 | 30.770 |
| host glibc final run | `[18.833 ns 18.875 ns 18.921 ns]` | 18.818 | 19.794 |

Compared with the focused baseline, the final candidate regressed p50
`26.984 -> 29.658 ns` and mean `27.657 -> 30.770 ns`.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`: passed
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs`: passed
- RCH `cargo check -j 1 -p frankenlibc-core --lib`: passed with pre-existing iconv warnings
- RCH `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings`: attempted; failed on pre-existing iconv/resolv/regex lint debt plus the candidate collapsible-if before source restore

## Verdict

REJECTED-RESTORED. Score: `0.0`.

Source restored; `git diff -- crates/frankenlibc-core/src/string/mem.rs` is
empty.

Do not retry `memchr_absent` hot/cold folded-hit outlining. Return only with a
genuinely different generated/backend primitive after a fresh focused gate.
