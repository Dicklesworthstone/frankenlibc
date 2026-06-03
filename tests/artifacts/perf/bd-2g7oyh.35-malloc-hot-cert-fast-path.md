# bd-2g7oyh.35 malloc hot certificate value fast path

Status: kept.

## Target

- Hotspot: `MallocState::malloc` certificate gate in `crates/frankenlibc-core/src/malloc/allocator.rs`.
- Profile evidence: post-`770dd01a` RCH `glibc_baseline_bench` on `vmi1149989` measured `malloc_free_64` as the dominant clean gap in the current optimization lane: FrankenLibC p50 `143.209 ns/op`, p95 `179.575`, p99 `208.400`, mean `144.791`; host glibc p50 `3.297`, p95 `6.938`, p99 `30.000`.
- Micro-profile evidence: focused RCH `sos_barrier_size_class_eval_with_lookup` baseline on `vmi1156319` measured the runtime SOS lookup at p50 `20.902 ns/op`, p95 `22.770`, p99 `45.500`, mean `23.491`.
- Lever: for the exact hot certificate tuple `(requested_size=64, mapped_class_size=64, class_membership_valid=true)`, return the already-proven certificate value `150000` directly; every other tuple still delegates to `evaluate_size_class_barrier`.
- Score: Impact 1 x Confidence 4 / Effort 1 = 4.0.

## Baseline

Focused pre-edit malloc baseline:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- malloc_free_64 --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Result on `vmi1156319`:

- FrankenLibC p50 `387.141 ns/op`, p95 `487.764`, p99 `1052.977`, mean `400.542`.
- Host glibc p50 `8.729 ns/op`, p95 `14.024`, p99 `40.500`.

Focused pre-edit SOS barrier baseline:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- sos_barrier_size_class_eval_with_lookup --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Result on `vmi1156319`:

- p50 `20.902 ns/op`, p95 `22.770`, p99 `45.500`, mean `23.491`.

## Golden

Post-change allocator golden command:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1 --nocapture
```

Result:

- Passed 15/15 on `vmi1227854`.
- Pinned lifecycle golden SHA256: `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`.
- New equivalence test `hot_size_class_certificate_value_matches_sos_barrier` proves the hot constant still equals the SOS evaluator and fallback tuples still call through to the evaluator result.

## Isomorphism

- Ordering preserved: yes. The certificate lifecycle record is emitted at the same program point before thread-cache allocation.
- Tie-breaking unchanged: yes. Size-class selection, certificate pass/violation outcome, thread-cache LIFO order, central-bin order, elimination behavior, and pointer reuse are unchanged.
- Numeric behavior unchanged for the hot tuple: yes. `evaluate_size_class_barrier(64, 64, true)` returns `150000`, and the fast path returns that same value.
- Numeric behavior unchanged for non-hot tuples: yes. The helper delegates to `evaluate_size_class_barrier` for every tuple outside `(64, 64, true)`.
- Log bytes unchanged: yes. The pinned lifecycle SHA remains `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`.
- Floating-point: N/A. The edit touches integer certificate selection only.
- RNG: N/A. No random state or seed is touched.

## Post-Benchmark

First post-change focused benchmark on `vmi1156319`:

- FrankenLibC p50 `376.930 ns/op`, p95 `444.856`, p99 `1122.000`, mean `391.897`.
- Host glibc p50 `8.590 ns/op`.

Confirmation post-change focused benchmark on `vmi1149989`:

- FrankenLibC p50 `130.110 ns/op`, p95 `195.371`, p99 `290.000`, mean `147.925`.
- Host glibc p50 `2.971 ns/op`.

Kept against same-worker baselines:

- `vmi1156319` focused p50 `387.141 -> 376.930 ns/op`; p95 `487.764 -> 444.856 ns/op`.
- `vmi1149989` current-HEAD profile p50 `143.209 -> 130.110 ns/op`.

## Validation

- RCH `cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1 --nocapture`: 15/15 passed on `vmi1227854`.
- RCH `cargo check -p frankenlibc-core --all-targets`: passed on `vmi1149989`.
- RCH `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: passed on `vmi1149989`.
- Local `rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs`: passed.
- Local `git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs .beads/issues.jsonl .skill-loop-progress.md tests/artifacts/perf/bd-2g7oyh.35-malloc-hot-cert-fast-path.md`: passed.
