# bd-2g7oyh.165 - memset slice-fill lowering deferred

## Decision

Deferred and restored. The one-line `memset` lowering from a manual byte loop to
`dest[..count].fill(value)` measured as a real same-worker win, but it is not
kept in this closeout because `bd-2g7oyh.166` claimed the same file
(`crates/frankenlibc-core/src/string/mem.rs`) and introduced live `memchr`
changes while this pass was underway. To avoid mixing ownership, no `.165`
source change is retained.

Score if the file is available later: `(Impact 2 * Confidence 4) / Effort 1 = 8.0`.

## Baseline Context

Initial focused memory-op profile selected worker `vmi1149989` despite the
requested worker:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=ts1 RCH_VISIBILITY=summary rch exec -- \
  env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench \
  --bench glibc_baseline_bench -- 'glibc_baseline_mem(move|cpy|set)_4096' \
  --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Rows on `vmi1149989`:

- `memcpy_4096`: FrankenLibC p50 `26.875 ns`, mean `28.954 ns`; host p50
  `28.640 ns`, mean `31.254 ns`.
- `memset_4096`: FrankenLibC p50 `19.556 ns`, mean `22.762 ns`; host p50
  `17.904 ns`, mean `20.019 ns`.
- `memmove_4096`: FrankenLibC p50 `30.180 ns`, mean `31.730 ns`; host p50
  `28.190 ns`, mean `29.451 ns`.

Because later post runs selected `ts1`, a controlled A/B was run on `ts1`.

## Attempted Lever

Replace:

```rust
for byte in &mut dest[..count] {
    *byte = value;
}
```

with:

```rust
dest[..count].fill(value);
```

The count computation, prefix bounds, return value, and value semantics are
unchanged.

## Behavior Proof

Focused proof command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1149989 RCH_VISIBILITY=summary rch exec -- \
  cargo test -p frankenlibc-core memset -- --nocapture --test-threads=1
```

RCH selected `ts1`; result passed:

- `string::mem::tests::prop_memset_only_mutates_requested_prefix`
- `string::mem::tests::test_memset_basic`
- `string::mem::tests::test_memset_partial`
- `string::wide::tests::prop_wmemset_overwrites_prefix_only`
- `string::wide::tests::test_wmemset_basic`
- `string_properties::prop_memset_fills_prefix`

Local focused checks passed:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
git diff --check -- crates/frankenlibc-core/src/string/mem.rs
```

Isomorphism ledger:

- Ordering preserved: N/A.
- Tie-breaking unchanged: N/A.
- Length clipping unchanged: yes; `count = n.min(dest.len())` remains the only
  bound.
- Mutation region unchanged: yes; only `dest[..count]` is written.
- Return value unchanged: yes; returns `count`.
- Floating point: N/A.
- RNG: N/A.

## Controlled A/B on ts1

A-side restored-loop baseline:

- `memcpy_4096`: FrankenLibC p50 `36.644 ns`, mean `38.129 ns`; host p50
  `35.443 ns`, mean `40.449 ns`.
- `memset_4096`: FrankenLibC p50 `36.376 ns`, mean `39.789 ns`; host p50
  `38.239 ns`, mean `41.075 ns`.
- `memmove_4096`: FrankenLibC p50 `43.580 ns`, mean `45.722 ns`; host p50
  `36.604 ns`, mean `38.353 ns`.

B-side `slice::fill` confirmation:

- `memcpy_4096`: FrankenLibC p50 `34.883 ns`, mean `39.319 ns`; host p50
  `34.409 ns`, mean `55.500 ns`.
- `memset_4096`: FrankenLibC p50 `34.455 ns`, mean `35.263 ns`; host p50
  `37.082 ns`, mean `38.307 ns`.
- `memmove_4096`: FrankenLibC p50 `45.140 ns`, mean `46.117 ns`; host p50
  `37.493 ns`, mean `42.110 ns`.

Target delta:

- `memset_4096` p50 improved from `36.376 ns` to `34.455 ns` (`5.3%`).
- `memset_4096` mean improved from `39.789 ns` to `35.263 ns` (`11.4%`).

Guard interpretation:

- `memcpy_4096` p50 improved; mean was tail-noisy.
- `memmove_4096` moved slightly in p50 and mean, but no `memmove` source was
  touched and host rows were also noisy across runs.

## Closeout

No `.165` source is kept. The live `mem.rs` diff belongs to `bd-2g7oyh.166`
(`memchr_absent folded probe residual`) and should be handled by that bead. The
`slice::fill` lowering is a good follow-up candidate once `mem.rs` is no longer
claimed by the `memchr` pass.
