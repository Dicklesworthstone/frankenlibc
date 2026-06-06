# bd-2g7oyh.170 memcmp 256-byte fold rejection

## Target

- Bead: `bd-2g7oyh.170`
- Scope: `crates/frankenlibc-core/src/string/mem.rs`
- Profile-backed target: equal-buffer `memcmp_4096`
- Candidate lever: use the existing 256-byte folded SIMD equality certificate for every large equal block, resolving only non-equal 256-byte blocks through the existing ordered 32-byte panel and byte resolver.

## Pre-edit baseline

Command:

```bash
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_memcmp_(16|256|4096)' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

RCH routed to `vmi1149989`.

| Row | FrankenLibC p50 | FrankenLibC mean | host p50 | host mean |
| --- | ---: | ---: | ---: | ---: |
| memcmp_16 | 3.230 ns | 5.070 ns | 1.719 ns | 2.578 ns |
| memcmp_256 | 4.291 ns | 5.489 ns | 3.172 ns | 4.953 ns |
| memcmp_4096 | 46.749 ns | 52.109 ns | 39.949 ns | 42.739 ns |

## Behavior proof

Focused unit/proptest proof:

```bash
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon cargo test -p frankenlibc-core --lib memcmp -- --nocapture
```

RCH routed to `vmi1156319`. Result: 30 passed, 0 failed. The candidate included a temporary `test_memcmp_large_256_fold_preserves_first_difference` guard; scalar-position and antisymmetry proptests passed.

Golden output proof:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon cargo test -p frankenlibc-core --test property_tests golden_memcmp_corpus_sha256 -- --nocapture
```

RCH routed to `vmi1227854`. Result: 1 passed, 0 failed. Golden SHA remained:

```text
23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e
```

Isomorphism notes:

- Ordering and tie-breaking: unchanged. The 256-byte certificate only answered "any byte differs"; any non-equal certificate fell back to the original 32-byte panel scan and `compare_bytes`, preserving the first differing byte and unsigned-byte sign.
- Floating point: N/A.
- RNG: N/A.

## Candidate post

Command:

```bash
RCH_WORKER=vmi1149989 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_memcmp_(16|256|4096)' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

RCH routed to `ts1`.

| Row | Candidate FrankenLibC p50 | Candidate FrankenLibC mean | host p50 | host mean |
| --- | ---: | ---: | ---: | ---: |
| memcmp_16 | 4.136 ns | 5.691 ns | 2.326 ns | 3.166 ns |
| memcmp_256 | 5.686 ns | 7.222 ns | 4.064 ns | 4.773 ns |
| memcmp_4096 | 53.500 ns | 56.119 ns | 45.201 ns | 46.975 ns |

Because the post routed to `ts1`, a clean same-worker baseline was run from scratch worktree `/data/projects/.scratch/frankenlibc-bd-2g7oyh-170-baseline-76e3f215` at commit `76e3f215`.

Clean source same-worker baseline command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_memcmp_(16|256|4096)' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

RCH routed to `ts1`.

| Row | Clean FrankenLibC p50 | Clean FrankenLibC mean | host p50 | host mean |
| --- | ---: | ---: | ---: | ---: |
| memcmp_16 | 3.911 ns | 4.764 ns | 2.416 ns | 3.012 ns |
| memcmp_256 | 5.491 ns | 6.322 ns | 3.435 ns | 4.273 ns |
| memcmp_4096 | 48.212 ns | 51.051 ns | 46.227 ns | 51.931 ns |

## Verdict

Rejected and restored. Same-worker `ts1` comparison regressed:

- `memcmp_4096`: 48.212 -> 53.500 ns p50, 51.051 -> 56.119 ns mean.
- `memcmp_16`: 3.911 -> 4.136 ns p50, 4.764 -> 5.691 ns mean.
- `memcmp_256`: 5.491 -> 5.686 ns p50, 6.322 -> 7.222 ns mean.

Score: 0.0. No source kept.

Next primitive: do not retry a larger outer equality-certificate loop. Attack a mask-producing first-difference locator/rank-select path that reduces resolver overhead without adding an extra equal-block branch on every large block.
