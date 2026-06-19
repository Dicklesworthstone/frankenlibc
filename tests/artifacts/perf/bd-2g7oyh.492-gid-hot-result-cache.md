# bd-2g7oyh.492 gid hot-result cache partial keep

Date: 2026-06-19
Agent: BlackThrush / cod-b
Bead: `bd-2g7oyh.492`
Target: `glibc_baseline_grp_lookup/getgrgid_0`

## Lever

`getgrgid(0)` was neutral after `bd-2g7oyh.481` even though the group-line
parser made `getgrnam("root")` a clear deployed ABI win. This lever does not
touch the parser. It caches the most recent successful gid lookup for the
current group-file generation and reuses the already-materialized TLS
`libc::group` when the same gid/generation is requested again. The faster C
`stat` fingerprint probe is restricted to the gid path so `getgrnam` keeps the
previous metadata path.

## Final candidate command

```bash
RCH_WORKER=hz1 RCH_PREFERRED_WORKER=hz1 RCH_WORKERS=hz1 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=BlackThrush FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b-candidate-hz1 \
  CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b-candidate-hz1/criterion-bd-2g7oyh-492-candidate-gidstat-hz1-20260619T0540 \
  cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- glibc_baseline_grp_lookup \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

`rch` selected worker `hz2`.

## Final result

| Workload | FrankenLibC p50 | glibc p50 | p50 ratio | FrankenLibC mean | glibc mean | mean ratio | Verdict |
|----------|-----------------|-----------|-----------|------------------|------------|------------|---------|
| `getgrnam_root` | 9.791 us | 24.739 us | 0.396x | 9.790 us | 25.044 us | 0.391x | WIN guard |
| `getgrgid_0` | 14.687 us | 15.179 us | 0.968x | 15.006 us | 15.986 us | 0.939x | p50 NEUTRAL, mean WIN |

Tail ratios for `getgrgid_0`: p95 `0.931x`, p99 `0.890x`.

Same-worker prior corrected-source `bd-2g7oyh.481` p50 on `hz2` was
FrankenLibC `24.631 us` vs glibc `24.435 us` (`1.008x`). This change reduces
FrankenLibC deployed gid lookup p50 by about `40.4%`, but the final p50 ratio
against glibc remains neutral under the ledger rule.

## Negative evidence

- Hot-result cache without the gid-only C stat probe was insufficient on a
  controlled `hz1` candidate: FrankenLibC `28.450 us` vs glibc `18.726 us`,
  ratio `1.519x`, with worse p95.
- Applying the C stat probe to all refreshes improved gid lookup but regressed
  the `getgrnam` guard. The kept version restricts the probe to gid lookup.
- Do not retry colon-tail parser reshaping from `bd-2g7oyh.481`; it already
  won `getgrnam` and did not solve gid lookup.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-abi/src/grp_abi.rs crates/frankenlibc-abi/tests/grp_abi_test.rs`: passed.
- `cargo test -p frankenlibc-abi --test grp_abi_test getgrgid_hot_lookup_reuses_tls_result_and_invalidates_on_reload -- --nocapture`: passed.
- Earlier same-turn focused guards passed:
  `cargo check -p frankenlibc-abi`;
  `cargo test -p frankenlibc-abi --test grp_abi_test getgr -- --nocapture`;
  `cargo test -p frankenlibc-abi --test conformance_diff_getbyid_r -- --nocapture`;
  `cargo test -p frankenlibc-abi --test conformance_diff_getgrent -- --nocapture`.

Workspace `cargo fmt --check` and clippy remain blocked by broad pre-existing
unrelated drift/warnings outside this bead.

## Retry predicate

Keep this as a measured partial keep, not a p50 domination claim. The next
attempt should target the remaining per-call fingerprint/stat cost, a
correctness-preserving invalidation primitive, or a different NSS lookup/cache
structure that clears the p50 win gate.
