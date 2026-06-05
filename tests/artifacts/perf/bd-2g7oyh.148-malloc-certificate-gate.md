# bd-2g7oyh.148 - malloc size-class certificate log gate

Status: kept.

## Target

- Bead: `bd-2g7oyh.148`
- Hotspot: `malloc_free_64`
- Source: `crates/frankenlibc-core/src/malloc/allocator.rs`
- Lever: skip successful size-class SOS certificate evaluation when the default
  `Warn` lifecycle-log gate would drop the diagnostic `Trace` row anyway.

Trace logging and potential certificate-violation paths still evaluate the
certificate and preserve the existing lifecycle record semantics.

## Profile Evidence

Post-commit broad RCH profile before this bead, on `vmi1153651`:

- `malloc_free_64` FrankenLibC p50 `12.447 ns`, p95 `18.383 ns`, p99 `40.000 ns`, mean `15.737 ns`
- `malloc_free_64` host glibc p50 `8.879 ns`, mean `12.302 ns`
- `malloc_free_256` FrankenLibC p50 `12.742 ns`, p95 `25.000 ns`, p99 `50.500 ns`, mean `15.953 ns`
- `malloc_free_256` host glibc p50 `8.727 ns`, mean `11.677 ns`

Focused RCH baseline on `ts1`:

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_malloc148_baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- malloc_free --noplot --sample-size 40 --measurement-time 3 --warm-up-time 1`
- `malloc_free_64` FrankenLibC p50 `10.999 ns`, p95 `15.000 ns`, p99 `30.000 ns`, mean `12.312 ns`
- `malloc_free_64` host glibc p50 `5.802 ns`, mean `8.054 ns`
- `malloc_free_256` FrankenLibC p50 `5.771 ns`, p95 `9.505 ns`, p99 `20.000 ns`, mean `6.807 ns`
- `malloc_free_256` host glibc p50 `4.963 ns`, mean `5.988 ns`

RCH post-bench on `ts2`:

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_malloc148_post cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- malloc_free --noplot --sample-size 40 --measurement-time 3 --warm-up-time 1`
- `malloc_free_64` FrankenLibC p50 `8.834 ns`, p95 `13.750 ns`, p99 `30.000 ns`, mean `10.690 ns`
- `malloc_free_64` host glibc p50 `8.004 ns`, mean `9.478 ns`
- `malloc_free_256` FrankenLibC p50 `8.861 ns`, p95 `13.750 ns`, p99 `25.000 ns`, mean `10.168 ns`
- `malloc_free_256` host glibc p50 `7.602 ns`, mean `8.982 ns`

RCH `malloc_free_64` confirmation on `ts2`:

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_malloc148_confirm64 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- malloc_free_64 --noplot --sample-size 40 --measurement-time 3 --warm-up-time 1`
- `malloc_free_64` FrankenLibC p50 `8.741 ns`, p95 `13.750 ns`, p99 `30.000 ns`, mean `10.487 ns`
- `malloc_free_64` host glibc p50 `8.056 ns`, mean `10.192 ns`

Primary kept row:

- `malloc_free_64` p50 `10.999 ns -> 8.741 ns`, `1.26x` faster
- `malloc_free_64` mean `12.312 ns -> 10.487 ns`, `1.17x` faster
- The final post evidence is cross-worker (`ts1` baseline, `ts2` post) because
  `rch exec` does not expose a worker pin. The `ts2` post and confirmation
  were stable and narrowed the host gap to about `0.685 ns` p50.

Score: Impact `3` x Confidence `4` / Effort `2` = `6.0`; keep.

## Isomorphism Proof

- Ordering preserved: yes. Allocation path order remains thread cache,
  elimination, central bin, backend refill; free path is unchanged.
- Tie-breaking preserved: yes. Thread-cache LIFO reuse, central-bin LIFO reuse,
  and elimination matching order are unchanged.
- Lifecycle records preserved: yes for Trace mode. Trace still evaluates the
  certificate and records the same size-class certificate rows. Default Warn mode
  still drops successful Trace rows; potential violation rows still evaluate the
  certificate and can record Warn diagnostics.
- Allocation accounting preserved: yes. `active_count`, `total_allocated`, cache
  hit/miss counters, central-bin counters, spill counters, and pointer values are
  not changed by the certificate gate.
- Floating point: not applicable.
- RNG: not applicable.

## Golden SHA-256

- `crates/frankenlibc-core/src/malloc/bounds_audit_fixture.json`:
  `d9fc3e111580ec85638701db06c7be9ba8413cfb28d7fe5cf3d9331f0d28f0af`
- `tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json`:
  `a70dc7fad4679910cf938a65e8a18b3fec0823d9c739f931345624e0b406bdc1`
- Built-in lifecycle golden stayed pinned by
  `hot_cycle_lifecycle_record_sha256_is_stable`:
  `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`

## Validation

- `rustfmt +nightly --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs`: pass
- `git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs`: pass
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_malloc148_final_malloc_tests cargo test -p frankenlibc-core malloc --lib -- --nocapture`
  - worker: `vmi1156319`
  - result: pass, 62/62.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_malloc148_final_check cargo check -p frankenlibc-core --all-targets`
  - worker: `vmi1153651`
  - result: pass.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_malloc148_clippy cargo clippy -p frankenlibc-core --all-targets -- -D warnings`
  - result: blocked by pre-existing unrelated lint debt in `regex.rs` and `wide.rs`; no
    diagnostics came from `malloc/allocator.rs`.
