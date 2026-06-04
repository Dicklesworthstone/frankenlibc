# bd-2g7oyh.51 - malloc symbolic lifecycle trace ids

Status: kept and closed.

## Target

- Bead: `bd-2g7oyh.51`
- Hotspot: `glibc_baseline_malloc_free_64`
- Owned source: `crates/frankenlibc-core/src/malloc/allocator.rs`
- Lever: store allocator lifecycle trace ids as `(symbol, decision_id)` and render the legacy
  `core::malloc::{symbol}::{decision_id:016x}` text only when a lifecycle row is observed.

This is the structural successor to rejected `bd-2g7oyh.50`, which tried an inline trace-id buffer
and regressed the allocator row.

## Baseline And Perf Evidence

Pre-symbolic profile evidence from the bead handoff:

- Broad RCH re-profile on `vmi1227854`: FrankenLibC `malloc_free_64` p50 `158.503 ns/op`, mean
  `161.148`; host glibc p50 `3.337`, mean `5.057`.
- Focused baseline on `vmi1264463`: FrankenLibC p50 `391.878 ns/op`, mean `499.700`; host p50
  `9.104`, mean `14.580`.

Post-symbolic confirmation from the original in-flight pass:

- RCH post on `vmi1156319`: FrankenLibC p50 `72.596 ns/op`, p95 `92.907`, p99 `231.000`, mean
  `92.605`; host p50 `8.531`, p95 `13.750`, p99 `40.000`, mean `10.595`.

Current-HEAD confirmation after later allocator work and the clippy comparison fix:

- RCH current run on `ts2`: FrankenLibC p50 `8.735 ns/op`, p95 `12.500`, p99 `25.000`, mean
  `9.991`; host p50 `7.648`, p95 `12.500`, p99 `25.000`, mean `9.203`.
- RCH post-fix run on `vmi1153651`: FrankenLibC p50 `12.876 ns/op`, p95 `25.000`, p99
  `100.000`, mean `16.514`; host p50 `8.790`, p95 `23.092`, p99 `35.000`, mean `11.460`.

Score for the symbolic lever: Impact `5` x Confidence `4` / Effort `2` = `10.0`; keep.

## Isomorphism Proof

- Ordering preserved: yes. `record_lifecycle` call sites, decision-id increments, and row push order
  are unchanged.
- Tie-breaking unchanged: yes. Trace-id representation is not involved in allocation policy,
  thread-cache order, central-bin order, elimination routing, or pointer choice.
- Floating-point: N/A. The edited allocator path performs integer/string metadata handling only.
- RNG: N/A. No random source is read or written.
- Golden outputs: the lifecycle golden row SHA remains
  `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`.
- Legacy text contract: `AllocatorTraceId` still renders and compares as
  `core::malloc::{symbol}::{decision_id:016x}`; the closeout fix compares that text without
  allocating an owned `String`.

## Validation

- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_51_lifecycle_after_cmp RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable --lib -- --exact --nocapture --test-threads=1`
  - worker: `vmi1153651`
  - result: pass, 1/1.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_51_check cargo check -p frankenlibc-core --all-targets`
  - worker: `ts2`
  - result: pass.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_51_clippy_lib cargo clippy -p frankenlibc-core --lib -- -D warnings -A clippy::question_mark -A clippy::too_many_arguments -A clippy::collapsible_if -A clippy::unnecessary_cast`
  - worker: `ts2`
  - result: pass.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs`
  - result: pass.
- `git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs`
  - result: pass.

Known unrelated blockers observed during closeout:

- `cargo fmt -p frankenlibc-core --check` is blocked by formatting drift in peer-touched
  `iconv`, regex/string/mem, stdio, and differential-probe files.
- Strict all-targets clippy is blocked by unrelated regex/sort/string/test-probe lint debt
  (`question_mark`, `too_many_arguments`, `collapsible_if`, `unnecessary_cast`, `type_complexity`,
  `byte_char_slices`, `approx_constant`, `manual_memcpy`, `manual_repeat_n`,
  `unnecessary_min_or_max`, and `needless_range_loop`).
