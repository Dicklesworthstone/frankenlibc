# bd-2g7oyh.169 memchr vector-mask no-code rejection

## Target

- Bead: `bd-2g7oyh.169`
- Intended hotspot: `glibc_baseline_memchr_absent`
- Scope: `crates/frankenlibc-core/src/string/mem.rs`
- Intended primitive: vector-mask / rank-select first-lane extraction, avoiding prior wider-SIMD and scalar SWAR word-group rejects.

## Routing Evidence

Corrected clean-source memory-op reprofile on `ts1` found an apparent unowned residual:

```text
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_(memcpy_4096|memmove_4096|memset_4096|memchr_absent|memcmp_4096)' \
  --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

Clean-source `memchr_absent` row:

- FrankenLibC: p50 `40.185 ns/op`, mean `43.321 ns/op`
- host glibc: p50 `24.681 ns/op`, mean `26.666 ns/op`

Other clean-source memory rows did not offer a stronger unowned target:

- `memcpy_4096`: FrankenLibC p50 `34.866`, host p50 `38.327`
- `memset_4096`: FrankenLibC p50 `35.634`, host p50 `36.162`
- `memmove_4096`: FrankenLibC p50 `48.847`, host p50 `42.600`, means near parity
- `memcmp_4096`: p50 gap present but noisy and recently rejected on related exact/equal-buffer levers

## Mandatory Focused Baseline

Focused baseline command before any source edit:

```text
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memchr_absent --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH selected worker `vmi1156319` rather than `ts1`. Same-worker focused row:

- FrankenLibC: p50 `43.242 ns/op`, p95 `51.205`, p99 `100.500`, mean `50.414`
- host glibc: p50 `45.005 ns/op`, p95 `58.342`, p99 `77.375`, mean `46.810`

The focused p50 target did not reproduce: FrankenLibC was slightly faster than host at p50 on the selected worker. The mean-only residual was small and tail-noisy, so the vector-mask lever did not meet the Score >= 2.0 gate before editing.

## Decision

- Source changes: none
- Behavior proof: not run because no lever was implemented
- Golden SHA: unchanged by construction; no source files staged
- Score: `0.0` for this pass because the mandatory focused baseline did not expose a credible same-worker target
- Status: no-code rejection / defer until a focused same-worker baseline reproduces the gap

Next primitive remains vector-mask / rank-select first-lane extraction if a future focused baseline reproduces a real `memchr_absent` gap. Do not retry scalar per-word `chunks_exact(WORD)` or wider folded-panel SIMD.
