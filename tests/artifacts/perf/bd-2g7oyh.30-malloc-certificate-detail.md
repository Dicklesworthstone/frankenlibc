# bd-2g7oyh.30 malloc size-class certificate detail proof

## Profile-backed target

Fresh post-AVX2 and post typed-index RCH profile showed `malloc_free_64` as the dominant remaining vs-upstream gap:

- Broad profile on `vmi1153651`: FrankenLibC p50 `874.552 ns/op`, p95 `1724.366`, p99 `1964.000`; host glibc p50 `9.383`, p95 `18.564`, p99 `35.500`.
- Focused controlled pre-change RCH baseline on `vmi1293453`: FrankenLibC p50 `321.154 ns/op`, p95 `361.590`, p99 `415.500`; host glibc p50 `4.400`, p95 `6.875`, p99 `35.000`.

Hot source target: `MallocState::malloc` emitted a size-class certificate lifecycle record with generic formatting on every profiled 64-byte small allocation:

```rust
format!(
    "requested_size={size};mapped_class_size={class_size};cert_value={size_class_cert_value}"
)
```

## One lever

Replace the hot 64-byte certificate detail with a byte-identical static string path:

```rust
"requested_size=64;mapped_class_size=64;cert_value=150000"
```

All other `(requested_size, mapped_class_size, cert_value)` triples use the original generic `format!` fallback.

## Score

- Impact: 3, because this removes generic formatting from the currently profiled `malloc_free_64` hot path.
- Confidence: 4, because the detail bytes are golden-hashed and the post benchmark is comparable against an almost identical host row.
- Effort: 1.
- Score: `3 * 4 / 1 = 12.0`, kept.

## Benchmark proof

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench glibc_baseline_malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Before, worker `vmi1293453`:

- FrankenLibC p50 `321.154 ns/op`, p95 `361.590`, p99 `415.500`, mean `323.695`.
- Host glibc p50 `4.400 ns/op`, p95 `6.875`, p99 `35.000`, mean `5.892`.

After, worker `vmi1227854`:

- FrankenLibC p50 `227.763 ns/op`, p95 `256.981`, p99 `337.748`, mean `223.498`.
- Host glibc p50 `4.403 ns/op`, p95 `6.281`, p99 `30.000`, mean `6.142`.

Result:

- p50 speedup: `321.154 -> 227.763 ns/op` = `1.41x`.
- p95 speedup: `361.590 -> 256.981 ns/op` = `1.41x`.
- p99 speedup: `415.500 -> 337.748 ns/op` = `1.23x`.
- Host p50 was effectively unchanged (`4.400 -> 4.403 ns/op`), so this is a comparable RCH result despite different worker IDs.

## Behavior proof

- Ordering preserved: lifecycle record emission order is unchanged. `size_class_certificate` is still recorded before the thread-cache allocation attempt.
- Tie-breaking unchanged: allocator bin selection, class membership, certificate pass/violation outcome, thread-cache order, central-bin order, and free path behavior are unchanged.
- Floating-point: N/A. The edited path uses integer equality and string selection only.
- RNG: N/A. The allocator path does not touch RNG state or seeds.
- Detail bytes preserved for the profiled hot case: the static string is byte-for-byte identical to the previous `format!` output for `size=64`, `class_size=64`, `cert_value=150000`.
- Fallback detail bytes preserved for all other certificate triples by keeping the original generic formatting expression in the fallback branch.

## Golden and validation

Pre-change golden command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable --lib -- --nocapture
```

Pre-change normalized exact test-line SHA256:

```text
99efb08f2b612ec70e03fe51ee73620e2965a682de888e3e16cf0c3de360a564
```

Post-change normalized exact test-line SHA256:

```text
99efb08f2b612ec70e03fe51ee73620e2965a682de888e3e16cf0c3de360a564
```

Additional validation:

- RCH `cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1`: passed 14/14.
- RCH `cargo check -p frankenlibc-core --all-targets`: passed.
- RCH `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: passed.
- RCH `cargo fmt --check -p frankenlibc-core`: refused as non-compilation under `RCH_REQUIRE_REMOTE=1`.
- Local `cargo fmt --check -p frankenlibc-core`: blocked by unrelated pre-existing formatting in `crates/frankenlibc-core/tests/strstr_golden_corpus_test.rs:69`.
- Local touched-file `rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs`: passed.
- Local `git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs`: passed.
