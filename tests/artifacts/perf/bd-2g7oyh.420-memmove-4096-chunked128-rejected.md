# bd-2g7oyh.422 memmove_4096 chunked128 rejection

Date: 2026-06-15
Agent: BoldFalcon
Baseline worker: ovh-a
Proof worker: vmi1227854
Post-screen worker: vmi1227854
Commit under test: d1cadba83
Canonical bead: bd-2g7oyh.422
Artifact filename retains pre-rebase local id bd-2g7oyh.420.

## Route

Current-head broad RCH routing on ovh-a kept
`glibc_baseline_memmove_4096/memmove_4096` as a possible residual:

- FrankenLibC p50/mean: 47.354 / 50.637 ns
- host glibc p50/mean: 33.188 / 39.423 ns

This row was admissible only for a non-repeat lowering/call-overhead primitive:
prior exact safe-SIMD copy panels, surface `copy_from_slice` branchbacks, whole
array-copy lowering, and inline-only hints were already accepted or rejected.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-420-baseline cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- memmove_4096 --sample-size 20 --warm-up-time 1 --measurement-time 3
```

Focused same-worker result on `ovh-a`:

- FrankenLibC Criterion interval: [35.253 ns 35.489 ns 35.742 ns]
- FrankenLibC p50/mean: 35.584 / 37.751 ns
- host glibc Criterion interval: [31.003 ns 31.111 ns 31.204 ns]
- host glibc p50/mean: 31.226 / 33.751 ns

The focused p50 and mean gap reproduced.

## Candidate

One source lever was tested and restored:

- replace the exact `n == 4096 && dest.len() == 4096 && src.len() == 4096`
  `copy_from_slice` branch with a generated safe-Rust 32 x 128-byte array-copy
  prefix;
- preserve the previous clamped fallback and whole-4096 array-copy fallback;
- keep all ABI raw-pointer overlap code untouched.

This was intended to test whether fixed chunk lowering could avoid the remaining
whole-copy call shape without unsafe code.

## Behavior Proof

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-420-proof cargo test -j 1 -p frankenlibc-core --lib memmove -- --nocapture --test-threads=1
```

Result on `vmi1227854`: passed 3/3 filtered tests:

- `memmove_exact_4096_array_copy_preserves_prefix_contract`
- `memmove_exact_4096_full_slice_preserves_payload`
- `test_wmemmove_basic`

Golden SHA-256 values therefore remained:

- exact-4096 prefix contract: `92ae7e54d1615da62e9a7750fdcd6280b788ce3e85e0bd993fca3d7e3b2747dc`
- exact full-slice payload: `4e441a3533bb2c10cd5649981d395744213e09a336746b5a3458fee4057205ec`

## Post Screen

RCH ignored the `ovh-a` worker preference for the post run and selected
`vmi1227854`, so this was used only as a candidate screen rather than accepted
same-worker proof.

Command:

```bash
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-420-post cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- memmove_4096 --sample-size 20 --warm-up-time 1 --measurement-time 3
```

Candidate result on `vmi1227854`:

- FrankenLibC Criterion interval: [30.274 ns 31.181 ns 32.148 ns]
- FrankenLibC p50/mean: 30.336 / 52.500 ns
- FrankenLibC p95/p99: 70.500 / 901.000 ns
- host glibc Criterion interval: [29.043 ns 30.156 ns 31.157 ns]
- host glibc p50/mean: 29.641 / 33.183 ns
- host glibc p95/p99: 42.500 / 151.000 ns

The candidate failed before same-worker control: p50 remained behind host and
mean/tails regressed badly.

## Verdict

REJECTED-RESTORED. Score: 0.0.

The source was restored and `crates/frankenlibc-core/src/string/mem.rs` returned
to SHA-256 `da6e98c17b996e9d3fc546f88c5a5216a6727833679061b668a3fd555551fb6c`.

## Reroute

Do not retry fixed-size chunked array-copy lowering for `memmove_4096`. The next
attempt on this row needs a different primitive, such as an ABI-level
non-overlap classification proof or a backend-specific generated copy artifact
with same-worker baseline/control/post evidence.
