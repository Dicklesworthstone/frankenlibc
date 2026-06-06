# bd-2g7oyh.164 - memcmp_16 exact two-word equality certificate rejection

## Decision

Rejected and restored. The exact 16-byte equality certificate improved the
`memcmp_16` row, but repeatedly regressed the guard row `memcmp_256` on the
same worker. No source change is kept.

Score: `(Impact 2 * Confidence 1) / Effort 2 = 1.0`.

## Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=ts1 RCH_VISIBILITY=summary rch exec -- \
  env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench \
  --bench glibc_baseline_bench -- 'glibc_baseline_memcmp_(16|256)' \
  --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Worker: `ts1`.

Rows:

- `glibc_baseline_memcmp_16`: FrankenLibC p50 `4.406 ns`, mean `5.686 ns`;
  host glibc p50 `2.367 ns`, mean `3.270 ns`.
- `glibc_baseline_memcmp_256`: FrankenLibC p50 `5.028 ns`, mean `5.831 ns`;
  host glibc p50 `3.385 ns`, mean `4.280 ns`.

## Attempted Lever

Exact 16-byte equality certificate in `crates/frankenlibc-core/src/string/mem.rs`:
load two native-endian `u64` words and return `Ordering::Equal` only when both
words match. All mismatches fell through to the existing ordered resolver, so
first-difference byte ordering stayed unchanged.

After the first post result regressed `memcmp_256`, the branch order was refined
to run the existing exact-256 certificate before the new exact-16 certificate.
That did not remove the guard-row regression.

## Behavior Proof

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=ts1 RCH_VISIBILITY=summary rch exec -- \
  cargo test -p frankenlibc-core memcmp -- --nocapture --test-threads=1
```

Result: passed on worker `vmi1227854`; 29 focused memcmp-related tests passed,
including `string_properties::golden_memcmp_corpus_sha256` and
`string_properties::prop_memcpy_then_memcmp_is_zero`. The only warning was the
existing missing-SMT-solver notice.

Focused formatting check:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
```

Result: passed.

Isomorphism ledger:

- Ordering preserved: yes; the added path returned `Equal` only after both
  8-byte words matched exactly, and all mismatches used the existing ordered
  byte resolver.
- Tie-breaking unchanged: yes; equal inputs remained equal, unequal inputs used
  the pre-existing first-difference logic.
- Length clipping unchanged: yes; `count = min(n, a.len(), b.len())` stayed the
  sole slice bound.
- Floating point: N/A.
- RNG: N/A.
- Golden outputs: focused golden memcmp corpus passed.

## Post Results

Same-worker post after the exact-16 branch:

- `memcmp_16`: FrankenLibC p50 `3.372 ns`, mean `5.156 ns`; host p50
  `2.572 ns`, mean `3.979 ns`.
- `memcmp_256`: FrankenLibC p50 `5.671 ns`, mean `6.968 ns`; host p50
  `3.769 ns`, mean `5.070 ns`.

Same-worker confirmation:

- `memcmp_16`: FrankenLibC p50 `2.697 ns`, mean `3.704 ns`; host p50
  `2.708 ns`, mean `3.686 ns`.
- `memcmp_256`: FrankenLibC p50 `5.450 ns`, mean `6.191 ns`; host p50
  `3.573 ns`, mean `4.568 ns`.

Same-worker post after reordering the existing exact-256 certificate before the
new exact-16 certificate:

- `memcmp_16`: FrankenLibC p50 `2.621 ns`, mean `3.798 ns`; host p50
  `2.679 ns`, mean `3.780 ns`.
- `memcmp_256`: FrankenLibC p50 `6.027 ns`, mean `6.829 ns`; host p50
  `4.055 ns`, mean `5.064 ns`.

## Rejection Reason

The primary row improved, but `memcmp_256` was the mandatory guard row because
the previous accepted optimization lives in the exact-256 equal path. The guard
row regressed against the focused pre-edit baseline in all post runs:

- Baseline `memcmp_256`: p50 `5.028 ns`, mean `5.831 ns`.
- Post 1: p50 `5.671 ns`, mean `6.968 ns`.
- Confirmation: p50 `5.450 ns`, mean `6.191 ns`.
- Reordered branch: p50 `6.027 ns`, mean `6.829 ns`.

The source was restored to the pre-attempt state. Next work should avoid adding
another top-level `memcmp` length branch that perturbs the accepted 256-byte path;
prefer a separate profile-backed residual such as `strchr_absent`, `strcpy_4096`,
or a deeper `memmove_4096` primitive if unowned.
