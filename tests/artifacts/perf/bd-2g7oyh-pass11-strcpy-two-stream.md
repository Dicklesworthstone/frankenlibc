# bd-2g7oyh.256 - strcpy_4096 NUL-prefix certificate + bulk copy

## Target

- Bead: `bd-2g7oyh.256`
- Function: `frankenlibc_core::string::str::strcpy`
- Source: `crates/frankenlibc-core/src/string/str.rs`
- Profile-backed residual: RCH `vmi1156319` broad profile after `e068de5e` showed
  `strcpy_4096` FrankenLibC p50 152.297 ns, mean 160.343 ns, p95 198.744 ns,
  p99 239.354 ns vs host glibc p50 74.933 ns, mean 80.975 ns.

## Alien Primitive

- Graveyard route: byte-control-plane scan plus certified bulk transfer.
- Artifact: prove a NUL-free prefix, resolve the first terminator exactly, then
  issue one bounded slice copy through the terminator.
- This is not the rejected final-block rank-select family from `bd-2g7oyh.246`
  and not the prior fused scan/store family from `bd-2g7oyh.144`: the lever
  changes the hot path from many per-block stores during scan to one bulk copy
  after the terminator certificate is known.

## Baseline

Focused RCH baseline selected `vmi1293453` despite the `vmi1156319` preference:

```text
RCH_WORKER=vmi1156319 RCH_PREFERRED_WORKER=vmi1156319 RCH_REQUIRE_REMOTE=1 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd256-baseline-vmi1156319 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_(strcpy_4096|strlen_4096|memcpy_4096|memmove_4096)' \
  --noplot --sample-size 45 --warm-up-time 1 --measurement-time 3
```

`vmi1293453` focused baseline:

- `strcpy_4096` FrankenLibC p50 70.140 ns, mean 74.037 ns.
- `strcpy_4096` host glibc p50 37.455 ns, mean 42.875 ns.
- Guard rows: `strlen_4096` FL p50 20.132 ns vs host 21.451 ns;
  `memcpy_4096` FL p50 29.856 ns vs host 30.570 ns;
  `memmove_4096` FL p50 34.064 ns vs host 28.843 ns.

The keep/reject comparison uses the same-worker `vmi1156319` broad pre-edit
profile because RCH did not route the post-run to `vmi1293453`.

## Change

One source lever in `strcpy`:

- Scan 512-byte NUL-control blocks without writing them immediately.
- If a block contains a NUL, resolve the exact byte by scalar scan from that
  block start, then copy `src[..copied]` once.
- If the first NUL is in the tail after all full blocks, copy `src[..copied]`
  once.
- Short/no-NUL/panic fallback paths remain unchanged.

## Isomorphism Proof

- Ordering preserved: yes. The first returned terminator is still the lowest
  byte offset whose value is `0`; block detection only certifies whether a
  block contains a terminator, and scalar resolution walks left-to-right.
- Tie-breaking unchanged: yes. There is only one first terminator; embedded
  later NUL bytes remain ignored.
- Floating-point: N/A.
- RNG: N/A.
- Golden output: unchanged. RCH `vmi1156319`:
  `cargo test -p frankenlibc-core strcpy -- --nocapture --test-threads=1`
  passed 5/5, including `test_strcpy_golden_transcript_sha256`, short
  trailing-dest preservation, and the no-NUL panic contract.

## Post-Benchmark

Cross-worker post on `vmi1152480` was recorded but not used as a keep gate:

- Candidate `strcpy_4096` FL p50 91.888 ns, mean 104.192 ns.
- Host p50 60.557 ns, mean 65.659 ns.

Same-worker keep gate on `vmi1156319`:

```text
RCH_WORKERS=vmi1293453 RCH_WORKER=vmi1293453 RCH_PREFERRED_WORKER=vmi1293453 \
  RCH_REQUIRE_REMOTE=1 rch exec -- env AGENT_NAME=BoldFalcon \
  FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd256-post2-vmi1293453 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_strcpy_4096' --noplot --sample-size 45 --warm-up-time 1 \
  --measurement-time 3
```

RCH selected `vmi1156319`; compare to the pre-edit broad profile on the same
worker:

- FrankenLibC p50 152.297 -> 117.405 ns (1.30x faster).
- FrankenLibC mean 160.343 -> 138.153 ns (1.16x faster).
- Host row drifted slower in the post-run: p50 74.933 -> 110.676 ns,
  mean 80.975 -> 114.690 ns, so the relative p50 ratio improved from 2.03x
  slower to 1.06x slower.

## Validation

- `rustfmt --edition 2024 crates/frankenlibc-core/src/string/str.rs --check`:
  passed.
- RCH `cargo test -p frankenlibc-core strcpy -- --nocapture --test-threads=1`:
  passed.
- RCH `cargo check -p frankenlibc-core --all-targets`: passed.
- RCH `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: failed
  only on unrelated existing lint families in `math/exp.rs`, `stdio/file.rs`,
  and `string/regex.rs`; no `str.rs` lint findings.

## Verdict

KEPT. Score = `(Impact 3 * Confidence 3) / Effort 1 = 9.0`.

Next route after this keep: reprofile. If `strcpy_4096` remains hot, attack a
deeper primitive than NUL-prefix certificate/bulk-copy, such as a bounded
speculative vector store with an exact rollback-free C-string observability
proof, or pivot to the next sampled string/memory residual.
