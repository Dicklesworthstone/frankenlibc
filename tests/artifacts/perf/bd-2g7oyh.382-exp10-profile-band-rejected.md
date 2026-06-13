# bd-2g7oyh.382 exp10 profile-band gate

Status: REJECTED, no source retained.

## Target

Fresh post-bd-2g7oyh.381 broad RCH profile selected double `exp10` as the
largest material math residual. The focused baseline reproduced a gap on the
profile workload `exp10(x) x in [0.5,2.5)`.

## Lever Tested

One safe-Rust f64 profile-band algorithm was tested in
`crates/frankenlibc-core/src/math/float.rs`:

- preserve exact integer exponent fast path first;
- for finite `x in [0.5,2.5]`, use a 1/16-centered `10^(k/16)` table plus a
  degree-12 Horner residual for `exp(ln(10) * r)`;
- keep the existing compensated `exp2` route for all other `[-50,50]`
  non-integer inputs and `libm::exp10` outside that range.

This was an alien-graveyard table/range-reduction primitive, but it did not win
on the same-worker Criterion gate.

## Behavior Proof

RCH worker: `vmi1153651`.

- `cargo test -j 1 -p frankenlibc-core --lib exp10 -- --nocapture --test-threads=1`
  passed on final tested source: 9 tests passed; f64 profile-band worst ULP was
  4 at `1.7910368838793396`; golden SHA for the profiled corpus was
  `36f161a55b204f0ab87b63c008b22cbd2a0b1cc8f9c4a1f405d789654e2bbe21`.
- `cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math diff_exp10_within_4_ulps -- --nocapture --test-threads=1`
  passed against host glibc on final tested source.
- Local allowlisted clippy for the touched core crate passed:
  `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings
  -A clippy::excessive_precision -A clippy::collapsible_if
  -A clippy::manual_contains -A clippy::type_complexity
  -A clippy::unnecessary_map_or`.
- Strict RCH clippy was not available on `vmi1153651`: the remote pinned nightly
  lacked the `clippy` component. Local strict clippy remains blocked by existing
  non-exp10 lint debt in `exp.rs`, `sort.rs`, `fnmatch.rs`, and `regex.rs`.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/float.rs`
  passed.

Isomorphism: integer powers, fallback ordering, non-profile fallback bits,
floating-point 4-ULP envelope, and ABI edge/tail behavior were preserved in the
tested lever. RNG and tie-breaking are not applicable.

## Benchmarks

Same-worker RCH Criterion worker: `vmi1153651`.

Command:

```text
env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/exp10 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Baseline worktree: `/data/projects/.scratch/frankenlibc-exp10-baseline-93988d9c`
at commit `93988d9c`.

Post worktree: `/data/projects/.scratch/frankenlibc-exp10-bd-2g7oyh-382` with
the candidate source applied.

| row | baseline p50 ns | baseline mean ns | post p50 ns | post mean ns | result |
| --- | ---: | ---: | ---: | ---: | --- |
| `exp10` FrankenLibC | 855.586 | 1074.733 | 949.128 | 1115.225 | regression |
| `exp10` host glibc control | 654.484 | 821.805 | 652.187 | 772.233 | control stable enough |
| `exp10f` FrankenLibC control | 618.643 | 708.306 | 631.000 | 693.421 | unrelated/no target |

Score: `0.0`; the lever failed the Score >= 2.0 keep gate.

## Closeout

The source change was manually restored with `apply_patch`; `git diff --
crates/frankenlibc-core/src/math/float.rs` is empty after restore. Behavior is
unchanged by retained code because no source lever remains.

Next route: do not retry this table/Horner family for double `exp10`. The next
algorithmic route should either replace the underlying `exp2`/exp reduction
primitive itself or move to the next profile-backed residual from a fresh broad
profile.
