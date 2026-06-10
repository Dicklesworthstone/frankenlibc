# bd-4ycflz: memcmp_4096 XOR folded equality probe rejected

## Scope

- Bead: `bd-4ycflz`
- Workload: `glibc_baseline_memcmp_4096`, equal 4096-byte buffers
- Source touched during candidate: `crates/frankenlibc-core/src/string/mem.rs`
- Candidate primitive: replace the four-lane `simd_ne` mask OR in
  `ne_simd_folded_128` with an XOR/OR byte-difference vector followed by one
  zero comparison.

## Candidate

```rust
let diff = (a0 ^ b0) | (a1 ^ b1) | (a2 ^ b2) | (a3 ^ b3);
diff.simd_ne(Simd::splat(0)).any()
```

The intended isomorphism was narrow: for each byte, `a != b` is equivalent to
`(a ^ b) != 0`; OR-reducing the four 32-byte panels preserves the same
non-equal certificate as OR-reducing the four `simd_ne` masks. First-difference
ordering is unchanged because this helper is only an equality certificate; the
existing ordered resolver still handles any non-equal block.

## Behavior Proof

- RCH `vmi1227854`, build `29879662679164951`:
  `cargo test -j 1 -p frankenlibc-core --lib memcmp -- --nocapture --test-threads=1`
  passed.
- RCH `vmi1227854`, build `29879662679164956`:
  `cargo test -j 1 -p frankenlibc-core --test property_tests golden_memcmp_corpus_sha256 -- --nocapture --test-threads=1`
  passed.
- Golden memcmp corpus SHA-256 stayed
  `23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e`.
- FP/RNG/tie-breaking: not applicable.

## Clean Baseline

Clean detached worktree:
`/data/projects/frankenlibc_pass38_baseline_20260610T0424` at `daaa3d54`.

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS' \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass38-memcmp-baseline-target-20260610T0427Z \
CRITERION_HOME=/data/tmp/frankenlibc-pass38-memcmp-baseline-criterion-20260610T0427Z \
rch exec -- cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memcmp_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH build `29879662679164977`, worker `vmi1227854`, exit `0`.

| impl | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 51.837 | 60.000 | 78.554 | 52.557 |
| host glibc | 42.724 | 51.234 | 65.000 | 44.625 |

## Candidate Post

Candidate detached worktree:
`/data/projects/frankenlibc_clean_pass38_rch_20260610T0402`.

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS' \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass38-memcmp-post-target-20260610T0418Z \
CRITERION_HOME=/data/tmp/frankenlibc-pass38-memcmp-post-criterion-20260610T0418Z \
rch exec -- cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memcmp_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH build `29879662679164969`, worker `vmi1227854`, exit `0`.

| impl | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 52.569 | 72.413 | 86.153 | 55.941 |
| host glibc | 41.453 | 60.250 | 100.000 | 46.092 |

## Verdict

Rejected and restored.

- Primary p50 regressed `51.837 -> 52.569 ns` (`+1.4%`).
- Primary mean regressed `52.557 -> 55.941 ns` (`+6.4%`).
- p95 and p99 also regressed.
- Score: `(Impact 0 * Confidence 4) / Effort 1 = 0.0`.

Restoration proof:

```bash
git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs
```

passed after restoring the original `simd_ne` mask OR implementation.

Next route: do not retry XOR/test-zero codegen selection, loop unrolling,
folded-panel widening, broadword extraction, or 64-lane rank/select on this
evidence. Reprofile first; if `memcmp_4096` remains a material same-worker
residual, the next useful step is an RCH-compatible assembly/codegen extraction
path before another source lever.
