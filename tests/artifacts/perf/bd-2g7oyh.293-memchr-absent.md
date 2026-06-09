# bd-2g7oyh.293 memchr_absent focused baseline miss

## Target

Fresh `memchr_absent` target selected from the pass-27 broad RCH profile on
`ovh-a`:

| row | fl p50 ns | host p50 ns | p50 ratio | fl mean ns | host mean ns | mean ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| broad `memchr_absent` | 27.026 | 17.792 | 1.519x | 27.026 | 17.905 | 1.509x |

Prior `bd-2g7oyh.271` was closed because focused baselines on other workers did
not reproduce the broad-profile gap. This bead therefore began with a fresh
focused baseline before any source edit.

## Focused RCH baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd293-baseline-20260609 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memchr_absent --noplot --sample-size 40 \
  --warm-up-time 1 --measurement-time 3
```

RCH selected `ovh-a`, matching the broad-profile worker. It rewrote the target
dir to `.rch-target-ovh-a-job-29879662679164274-1781032179681652364-0`.

Focused rows:

| row | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC `memchr_absent` | 20.751 | 21.894 | 23.875 | 35.000 |
| host glibc `memchr_absent` | 18.139 | 19.442 | 21.536 | 35.000 |

Criterion estimate intervals:

- FrankenLibC time: `[20.792 ns, 20.854 ns, 20.929 ns]`
- host glibc time: `[17.979 ns, 18.056 ns, 18.149 ns]`

## Verdict

No-code rejected, Score `0.0`.

The focused same-worker gap is only `1.14x` p50 / `1.13x` mean and does not
justify touching `mem.rs`, especially after several rejected memchr families.
No source was edited, so ordering, first-match semantics, tie-breaking,
floating-point, RNG, and golden outputs are unchanged by construction.

Next route: continue from the same broad profile. `strlen_4096` is the next
unowned reproduced row (`1.373x` p50 / `1.365x` mean in the broad profile);
it must get its own focused RCH baseline before any source edit.
