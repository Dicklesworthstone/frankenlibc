# bd-95dz8v metadata RCU writer self-wait proof

Date: 2026-06-02
Agent: BlackThrush
Subsystem: `frankenlibc-bench` metadata read benchmark

## Profile-backed target

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_ENABLE_METADATA_BENCH=1 FRANKENLIBC_METADATA_BENCH_TRIALS=2 FRANKENLIBC_METADATA_BENCH_OPS_PER_THREAD=256 FRANKENLIBC_METADATA_BENCH_SAMPLE_STRIDE=4 cargo bench -p frankenlibc-bench --bench metadata_read_bench
```

Before:

- Worker: `vmi1293453`
- Job: `29869223945700850`
- The run emitted all-read `thread_metadata ratio=100` rows through `threads=64`.
- It made no row progress at the first write-bearing scenario for several minutes and was cancelled.
- Stable stall signature sha256: `07cec2ad784fdfda834f24c8c21b6564eb0dfe7fb28b7e51c23205dffc20650f`

Representative pre-stall rows:

```text
METADATA_BENCH operation=thread_metadata ratio=100 threads=1 rcu_ops_s=27367970.922 mutex_ops_s=38612368.024
METADATA_BENCH operation=thread_metadata ratio=100 threads=64 rcu_ops_s=5375010.662 mutex_ops_s=6894122.786
```

## Single lever

`RcuMetadataCell::write` now temporarily unregisters the current benchmark worker before waiting for the post-publish grace period, then re-registers the worker before returning to mixed read/write operations.

This changes only the benchmark harness. Production RCU APIs and benchmark record aggregation are unchanged.

## Isomorphism proof

- Ordering: unchanged. The same operation, ratio, thread-count, trial, and cursor schedule drives the worker loops.
- Tie-breaking: not applicable; the benchmark records every matrix entry and does not choose between equal candidates during execution.
- Floating point: unchanged. Throughput and latency summary arithmetic remains in the existing aggregation code.
- RNG: not applicable. The cursor and read/write split are deterministic.
- Schema: unchanged. Output still uses `METADATA_BENCH ... rcu_ops_s=... mutex_ops_s=...` rows plus `METADATA_BENCH_SUMMARY`.
- Memory reclamation invariant: unchanged for readers. The writer holds no RCU snapshot after publishing the new pointer, so removing its own registered reader slot during the grace-period wait prevents self-wait without exposing `old_ptr` to active readers.

## After

Worker: `vmi1227854`
Job: `29869223945701061`
Remote duration: `206.0s`

The same reduced matrix completed and emitted all 210 records:

```text
METADATA_BENCH_SUMMARY records=210 break_even_entries=21 out_dir=target/metadata_read_bench
```

Stable summary sha256: `2fafeb2387a7b536c29e40da71d6308e7e7730ca431dfa36b0c5ba631f24eace`

Representative write-bearing rows:

```text
METADATA_BENCH operation=thread_metadata ratio=99 threads=1 rcu_ops_s=879725085.911 mutex_ops_s=593967517.401
METADATA_BENCH operation=thread_metadata ratio=50 threads=64 rcu_ops_s=3149.425 mutex_ops_s=4359871.407
METADATA_BENCH operation=tls_cache_lookup ratio=50 threads=64 rcu_ops_s=4188.277 mutex_ops_s=2683301.916
```

## Validation

- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-bench --bench metadata_read_bench` passed on `vmi1153651`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-bench --bench metadata_read_bench -- -D warnings` passed on `vmi1153651`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo fmt -p frankenlibc-bench --check` was refused by `rch` as a non-compilation command under remote-required mode.
- `cargo fmt -p frankenlibc-bench --check` passed locally.
- `git diff --check -- crates/frankenlibc-bench/benches/metadata_read_bench.rs` passed locally.

## Keep score

Impact: 5. The benchmark moved from non-completion at first write-bearing scenario to full 210-record completion.
Confidence: 5. Static self-wait proof matches the observed stall and the after-run completion.
Effort: 1. One benchmark-harness helper and two call-site substitutions.
Score: 25.0.
