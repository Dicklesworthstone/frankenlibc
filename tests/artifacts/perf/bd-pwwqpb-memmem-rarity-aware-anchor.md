# bd-pwwqpb - memmem rarity-aware anchor table

Date: 2026-06-21
Agent: cod-a / BlackThrush
Worker: hz1
Target dir: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a`
Scope: `frankenlibc-core` source plus perf ledger only; no new `.scratch` or worktree.

## Lever

`memmem` already had two exact anchors for non-singleton needles: the first
needle byte at `cand` and the last needle byte at `cand + needle_len - 1`.
The old committed path always chose the last-byte `memchr` scan when the two
anchors differed. That is ideal for `aaaa...b` adversarial inputs, but bad for
ordinary text needles that end in common bytes such as `e`, `t`, or space.

The shipped change adds a static 256-entry byte-commonness table and chooses
the last anchor only when its table score is no higher than the first anchor's
score. The first-byte path also checks the last byte before the full compare.
The Two-Way bailout and leftmost result contract are unchanged.

## Scorecard

Primary acceptance row, same worker `hz1`:

| group | baseline fl | final fl | final glibc | final ratio | verdict |
|-------|-------------|----------|-------------|-------------|---------|
| `survey_memmem` text `needle_here` | 209.40 ns | 32.899 ns | 35.173 ns | 0.94x | WIN |
| `survey_strstr` same text needle | prior ledger 99.77 ns; final 49.198 ns | 49.198 ns | 45.162 ns | 1.09x | gap cut, residual loss |
| `survey_memmem_rarelast` | 13.637 ns | 13.611 ns | 35.513 ns | 0.38x | no regression, WIN |
| `survey_memmem_twoway` | 15.493 ns | 14.903 ns | 362.71 ns | 0.041x | no regression, WIN |

Extra committed diagnostic rows from the same final `survey_memmem` run:

| group | final fl | final glibc | ratio |
|-------|----------|-------------|-------|
| `survey_memmem_cand1` | 13.670 ns | 46.591 ns | 0.29x |
| `survey_memmem_cand4` | 28.855 ns | 47.045 ns | 0.61x |

## Rejected Intermediate Cut

The first candidate used a branchy `match byte.to_ascii_lowercase()` classifier.
It won the primary row but regressed the rare-last guard:

| group | branchy fl | branchy glibc | note |
|-------|------------|---------------|------|
| `survey_memmem` | 35.782 ns | 42.215 ns | primary win |
| `survey_memmem_rarelast` | 27.454 ns | 36.071 ns | self-regressed vs 13.637 ns baseline |

That branchy cut was not committed. The final table-based version recovered
the rare-last row and is the only source change kept.

## Commands

Baseline:

```sh
env AGENT_NAME=cod-a BR_AGENT_NAME=cod-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary \
  rch exec -- cargo bench -p frankenlibc-bench \
    --bench string_inprocess_survey_bench -- survey_memmem \
    --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

Final combined bench:

```sh
env AGENT_NAME=cod-a BR_AGENT_NAME=cod-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_WORKER=hz1 RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary \
  rch exec -- cargo bench -p frankenlibc-bench \
    --bench string_inprocess_survey_bench -- survey_memmem \
    --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

`strstr` inherited check:

```sh
env AGENT_NAME=cod-a BR_AGENT_NAME=cod-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_WORKER=hz1 RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary \
  rch exec -- cargo bench -p frankenlibc-bench \
    --bench string_inprocess_survey_bench -- 'survey_strstr/' \
    --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

Conformance/golden:

```sh
env AGENT_NAME=cod-a BR_AGENT_NAME=cod-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_WORKER=hz1 RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary \
  rch exec -- cargo test -p frankenlibc-core memmem -- --nocapture --test-threads=1
```

Result: 11 passed, 0 failed, 1 ignored. Includes
`memmem_golden_output_sha256`.

```sh
env AGENT_NAME=cod-a BR_AGENT_NAME=cod-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_WORKER=hz1 RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary \
  rch exec -- cargo test -p frankenlibc-core strstr -- --nocapture --test-threads=1
```

Result: 10 passed, 0 failed. `strstr_golden_corpus_digest_is_pinned`
passed and printed:
`STRSTR_GOLDEN_SHA256=4cbd66be7606fdc9012d7f842d58794b4c0efdfb113935faa65bb783e98a07e8`.

## Source Invariants

- Empty-needle, single-byte, and too-long-needle behavior unchanged.
- Both prefilter paths still return the first candidate whose full slice equals
  the needle.
- The Two-Way fallback still handles excessive failed candidate work and keeps
  the documented O(n + m) bound.
- Anchor selection only changes which exact candidate positions are skipped to
  first; it does not relax the full equality check.
