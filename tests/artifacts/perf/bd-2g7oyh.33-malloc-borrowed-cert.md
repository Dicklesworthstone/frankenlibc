# bd-2g7oyh.33 malloc borrowed certificate detail

Status: kept.

## Target

- Hotspot: `size_class_certificate_details` in `crates/frankenlibc-core/src/malloc/allocator.rs`.
- Profile evidence: fresh RCH `glibc_baseline_bench` after `bd-2g7oyh.32` rejection measured `malloc_free_64` at FrankenLibC p50 `353.242 ns/op`, p95 `561.802`, p99 `878.315`; host glibc p50 `5.312`.
- Focused baseline: current tree before edit on `vmi1227854` measured FrankenLibC p50 `240.465 ns/op`, p95 `279.765`, p99 `332.667`; host p50 `4.063`.
- Lever: for the exact hot certificate triple `requested_size=64`, `mapped_class_size=64`, `cert_value=150000`, return `Cow::Borrowed(HOT_CERT_64_DETAILS)` instead of allocating `Cow::Owned(HOT_CERT_64_DETAILS.to_owned())`.
- Score: Impact 1 x Confidence 4 / Effort 1 = 4.0.

## Golden

Pre-change command:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable --lib -- --exact --nocapture --test-threads=1
```

Post-change command: same.

Result:

- Pre-change: passed on `vmi1227854`.
- Post-change: passed on `vmi1149989`.
- Pinned lifecycle golden SHA256: `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`.

## Isomorphism

- Ordering preserved: yes. The certificate lifecycle record is emitted at the same point before thread-cache allocation.
- Tie-breaking unchanged: yes. Size-class selection, certificate pass/violation outcome, thread-cache LIFO order, central-bin order, and elimination behavior are unchanged.
- Log details unchanged: yes. The hot path returns the same byte string as before; only Cow storage changes from owned to borrowed.
- Floating-point: N/A. The edit touches only a string storage choice.
- RNG: N/A. No random state or seed is touched.
- Golden outputs: unchanged via the pinned lifecycle SHA test above.

## Post-Benchmark

Post-change focused benchmark on `vmi1227854`:

- First post: FrankenLibC p50 `218.663 ns/op`, p95 `318.379`, p99 `323.303`; host p50 `3.398`.
- Confirmation post: FrankenLibC p50 `232.511 ns/op`, p95 `278.142`, p99 `315.917`; host p50 `5.000`.

Kept against the focused baseline:

- p50 `240.465 -> 232.511 ns/op`.
- p95 `279.765 -> 278.142 ns/op`.
- p99 `332.667 -> 315.917 ns/op`.

## Validation

- RCH `cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1`: 14/14 passed on `vmi1153651`.
- RCH `cargo check -p frankenlibc-core --all-targets`: passed on `vmi1153651`.
- RCH `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: passed on `vmi1153651`.
- Local `rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs`: passed.
- Local `git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs`: passed.
