# bd-fop8o8 membrane foreign nonempty-oracle fast-path proof

Date: 2026-06-02
Agent: BlackThrush
Subsystem: `frankenlibc-membrane` pointer validation

## Profile-backed target

Baseline command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench membrane_bench -- --sample-size 30 --measurement-time 2 --warm-up-time 1
```

Baseline worker: `vmi1227854`
Baseline job: `29869223945701106`

Relevant current-main rows:

```text
MEMBRANE_BENCH mode=strict bench=validate_null samples=57 p50_ns_op=11.232 p95_ns_op=18.899 p99_ns_op=40.000 mean_ns_op=26.072 throughput_ops_s=85243412.852
MEMBRANE_BENCH mode=strict bench=validate_foreign samples=56 p50_ns_op=18.745 p95_ns_op=45.000 p99_ns_op=57.893 mean_ns_op=31.774 throughput_ops_s=51828782.255
MEMBRANE_BENCH mode=strict bench=validate_foreign_nonempty_oracle samples=50 p50_ns_op=1326.548 p95_ns_op=1675.568 p99_ns_op=1730.366 mean_ns_op=1258.333 throughput_ops_s=735621.995
MEMBRANE_BENCH mode=strict bench=validate_known samples=56 p50_ns_op=20.745 p95_ns_op=51.597 p99_ns_op=76.801 mean_ns_op=51.442 throughput_ops_s=42137692.951
```

Baseline target-row sha256: `af870f152d3d629cb5ae02433531cf1a774cd56637b699529d408f56e805aa85`

## Single lever

`ValidationPipeline::validate` already takes no-log fast exits for null, TLS-cache hits, and empty-oracle foreign pointers. This lever extends the foreign fast exit to the non-empty oracle case when both ownership filters reject the address:

- `bloom.might_contain(addr) == false`
- `page_oracle.query(addr) == false`

Owned pages and possible bloom hits still fall through to the full validation pipeline.

## Isomorphism proof

- Ordering: unchanged for any owned, cached, null, bloom-hit, or page-owned address. The new shortcut only covers the full path's bloom-miss plus page-oracle-miss terminal `Foreign` case.
- Tie-breaking: not applicable; pointer validation does not choose among equal candidates on this fast path.
- Floating point: not applicable to validation behavior. Benchmark aggregation is unchanged.
- RNG: not applicable. The validation and benchmark addresses are deterministic.
- Output behavior: the fast no-log result is exactly equal to the logged full-path result for a foreign address while the page oracle contains a live allocation.
- Safety guard: an interior pointer on an owned page still does not classify as `Foreign`.

Behavior proof lines:

```text
test ptr_validator::tests::default_nonempty_oracle_foreign_fast_path_matches_logged_pipeline_foreign ... ok
test ptr_validator::tests::interior_pointer_on_owned_page_is_not_misclassified_as_foreign ... ok
```

Behavior proof sha256: `2520875dbc373990083bc11639973f816e8379a85a90740097cc03c4c3e46f69`

## After

After command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench membrane_bench -- --sample-size 30 --measurement-time 2 --warm-up-time 1
```

After worker: `vmi1153651`
After job: `29869223945701140`

Target row:

```text
MEMBRANE_BENCH mode=strict bench=validate_foreign_nonempty_oracle samples=55 p50_ns_op=29.593 p95_ns_op=43.747 p99_ns_op=60.000 mean_ns_op=47.355 throughput_ops_s=31539695.769
```

After target-row sha256: `86b8e1a4fda5225ffb0fd00c0af8414e4072bc1cbbe5e9b82b7e2e7572854887`

Measured win:

- p50: `1326.548 ns -> 29.593 ns`
- p95: `1675.568 ns -> 43.747 ns`
- target throughput: `735,621.995 ops/s -> 31,539,695.769 ops/s`

## Validation

- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-membrane default_nonempty_oracle_foreign_fast_path_matches_logged_pipeline_foreign -- --nocapture` passed on `vmi1149989`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-membrane interior_pointer_on_owned_page_is_not_misclassified_as_foreign -- --nocapture` passed on `vmi1149989`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-membrane --all-targets` passed on `vmi1153651`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-membrane --all-targets -- -D warnings` passed on `vmi1153651`.
- `cargo fmt -p frankenlibc-membrane --check` passed locally.
- `git diff --check -- crates/frankenlibc-membrane/src/ptr_validator.rs` passed locally.

Source sha256 after change: `442045c54d583186863e8c981ff9d0edba5a295f7de1dedc1658f4d7bf99b38f`

## Keep score

Impact: 5. The remaining composed foreign validation hotspot moved from microsecond scale to tens of ns.
Confidence: 5. Fresh profile, direct behavior equality proof, and existing owned-page safety guard all agree with the root cause.
Effort: 1. One helper extension and one focused test.
Score: 25.0.
