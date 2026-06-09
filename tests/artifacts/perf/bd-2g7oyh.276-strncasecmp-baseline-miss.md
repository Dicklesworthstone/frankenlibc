# bd-2g7oyh.276 strncasecmp focused baseline miss

Timestamp: 2026-06-09T02:22:00Z
Agent: BoldFalcon

## Target

`bd-2g7oyh.276` targeted `glibc_baseline_strncasecmp_256_equal`, a
256-byte case-insensitive equal compare. The bead was filed from a broad RCH
profile on `ovh-a` that reported:

- FrankenLibC p50 `16.377 ns`, mean `21.092 ns`
- host glibc p50 `7.003 ns`, mean `9.746 ns`

Planned lever was a folded multi-panel ASCII-case SIMD reduction for
`strncasecmp`, preserving scalar exact-byte resolution for ordering, NUL, and
`n`-bound semantics.

## Focused Baseline Gate

Before editing, I reran the focused benchmark via RCH from the clean detached
worktree:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strncasecmp_256_equal --noplot --sample-size 30 --warm-up-time 1 --measurement-time 3
```

RCH selected `ovh-a`.

Focused result:

- FrankenLibC p50 `9.046 ns`, mean `11.493 ns`, p95 `11.250 ns`, p99 `40.500 ns`
- host glibc p50 `9.653 ns`, mean `11.099 ns`, p95 `13.750 ns`, p99 `25.000 ns`

The broad-profile gap did not reproduce. FrankenLibC was faster on p50 and only
`3.5%` slower on mean, so the profile-backed edit gate failed.

## Behavior Proof

No source change was kept. The behavior proof is therefore unchanged by
construction, and I also reran the committed casefold tests on RCH `ovh-a`:

```text
RCH_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 FRANKENLIBC_PROPTEST_CASES=256 cargo test -p frankenlibc-core --test property_tests golden_strcasecmp_corpus_sha256 -- --nocapture --test-threads=1
```

Result: passed. The pinned corpus SHA remains
`a530194ccf71c311a33c76a479c1db79832ab66ced74b16c338273157c7cd842`.

```text
RCH_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 FRANKENLIBC_PROPTEST_CASES=256 cargo test -p frankenlibc-core --test property_tests string_properties::prop_strncasecmp_matches_scalar_reference -- --exact --nocapture --test-threads=1
```

Result: passed. This pins ordering, tie-breaking/sign, NUL stop, and `n`-bound
semantics against the scalar reference. Floating-point and RNG behavior are not
involved in this string routine.

`git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs` passed.

The first proof attempt selected `ovh-b` and failed before tests with a
`zerocopy` build-script `SIGILL`; the proof was rerun successfully on `ovh-a`.

## Verdict

NO-CODE REJECTED, Score `0.0`.

Reason: the focused same-worker baseline did not reproduce a meaningful
FrankenLibC-vs-glibc gap. Optimizing here would violate the profile-backed
target rule.

Next route: reprofile before selecting another string target. If a
case-insensitive compare gap reappears as a focused same-worker residual, attack
it with a structurally different folded multi-panel casefold primitive and the
same scalar/golden proof gate; otherwise move to the fresh top residual.
