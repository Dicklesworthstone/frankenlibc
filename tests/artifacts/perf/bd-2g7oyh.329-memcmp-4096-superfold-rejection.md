# bd-2g7oyh.329 - memcmp_4096 exact-4096 superfold rejection

## Scope

- Bead: `bd-2g7oyh.329`
- Function: `frankenlibc_core::string::mem::memcmp`
- Workload: `glibc_baseline_memcmp_4096`, equal 4096-byte buffers
- Candidate worktree: `/data/projects/frankenlibc_b329_clean_20260610T2010`
- Candidate source: `crates/frankenlibc-core/src/string/mem.rs`

## Profile Basis

The bead was opened from a clean detached reprofile at `d63c4532` on RCH
`vmi1227854`:

| impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 53.848 | 55.943 | 64.619 | 80.443 |
| host glibc | 39.451 | 41.832 | 45.125 | 75.000 |

That is valid routing evidence for a focused memcmp pass. It is not, by itself,
a keep decision for a new source change.

## Candidate Audited

The in-flight candidate added an exact `count == 4096` branch that scans eight
512-byte blocks. Each 512-byte block folds sixteen 32-byte SIMD inequality
panels into one equality certificate and resolves any non-equal certificate by
falling back through the existing 128-byte block, 32-byte panel, then byte-wise
first-difference resolver.

Intended behavior proof:

- Ordering preserved: yes in the candidate design, because non-equal blocks are
  resolved in increasing address order and final sign still comes from the first
  differing unsigned byte.
- Tie-breaking preserved: yes; an equal 4096-byte prefix returns `Equal`, and
  non-equal prefixes delegate to the existing resolver.
- Floating-point: N/A.
- RNG: N/A.

## Rejection Reason

This is not a materially different primitive from prior rejected memcmp
families. It is another larger folded equality-certificate branch:

- `bd-2g7oyh.170` rejected a 256-byte folded equality-certificate loop because
  same-worker `memcmp_4096` regressed from `48.212 -> 53.500 ns` p50.
- `bd-2g7oyh.173` rejected a 512-byte folded block candidate. Best post was a
  weak `62.019 -> 59.498 ns` p50 move and confirmation collapsed to
  `61.192 ns`, Score `1.0`.
- `bd-4ycflz` and related artifacts explicitly route away from loop unrolling,
  folded-panel widening, broadword extraction, and rank/select repeats unless a
  fundamentally different codegen-backed primitive is first proven.

The only fresh candidate post run observed this pass was RCH build
`29879662679165699` on `vmi1227854`, command:

```text
env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd329-post-criterion-20260610T2027 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memcmp_4096 --noplot --sample-size 50 --warm-up-time 1 \
  --measurement-time 3
```

That run is not valid keep/reject proof because it overlapped other active
`vmi1227854` jobs, including a concurrent FrankenLibC baseline attempt
(`29879662679165696`) and multiple other project benchmarks. The baseline run
was cancelled once the overlap was detected. No local Criterion artifact was
available after sync-down for the completed candidate run.

## Verdict

Rejected; no source is kept on `main`.

Score: `(Impact 0 * Confidence 5) / Effort 2 = 0.0`.

Next route: stop repeating folded equality-certificate variants for
`memcmp_4096`. If memcmp remains a top residual after a fresh profile, the next
admissible primitive needs to be materially different: for example a
codegen/assembly-backed dispatch artifact, a safe-Rust backend that proves a
different load/test shape before source edit, or a separate top profile row.
