# bd-2g7oyh.495 passwd uid hot-result cache partial keep

Date: 2026-06-20
Agent: BlackThrush / cod-b
Bead: `bd-2g7oyh.495`
Target: `baseline_capture_bench` group `nss_passwd_lookup`

## Lever

The prior passwd parser lever (`bd-2g7oyh.482`) was measured reject/revert and
left a large deployed ABI `getpwuid(0)` gap. This attempt stays out of the
parser and targets lookup/cache behavior:

- generation-scoped cache for the last successful uid lookup;
- reuse of the already-materialized TLS `libc::passwd` for the same uid and
  same file generation;
- C `stat` fingerprint probe only on uid lookup paths, matching the successful
  group gid-cache shape from `bd-2g7oyh.492`;
- file reload/read failure/env-path changes clear the uid cache.

## Commands

Candidate and baseline used the same bench command shape:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR,AGENT_NAME \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench baseline_capture_bench nss_passwd_lookup \
  -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

Same-worker baseline source: detached worktree at `c1d89cd58`.
Candidate source: `cod-b-passwd-cache-20260620` scratch worktree.

## Same-worker hz1 result

| Source | Workload | FL p50 | glibc p50 | p50 ratio | FL Criterion | glibc Criterion | Verdict |
|---|---|---:|---:|---:|---:|---:|---|
| baseline `c1d89cd58` | `getpwuid_0_glibc_comparable` | 23.970 us | 9.042 us | 2.651x | 22.650 us | 9.097 us | LOSS |
| candidate | `getpwuid_0_glibc_comparable` | 17.881 us | 13.144 us | 1.361x | 19.038 us | 13.302 us | LOSS vs glibc, WIN vs old FL |

Same-worker FL-only speedup:

- p50: `23.970 -> 17.881 us`, `0.746x`, `-25.4%`.
- Criterion estimate: `22.650 -> 19.038 us`, `0.840x`, `-16.0%`.
- p95: `34.776 -> 27.371 us`, `0.787x`.

The same-worker glibc arm was noisier in the candidate run, so this is accepted
as a measured old-FL improvement, not as final p50 domination over glibc.

## Cross-worker corroboration

`rch` routed a repeat candidate run to `ovh-a`.

| Workload | FL p50 | glibc p50 | p50 ratio | FL mean | glibc mean | mean ratio | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| `getpwnam_root_glibc_comparable` | 9.386 us | 10.109 us | 0.929x | 11.571 us | 10.594 us | 1.092x | p50 WIN guard, mean LOSS |
| `getpwuid_0_glibc_comparable` | 11.426 us | 10.099 us | 1.131x | 11.006 us | 11.666 us | 0.943x | p50 LOSS, mean WIN |

The guard is recorded only as no-regression evidence. The lever is uid-only and
does not claim a name-lookup optimization.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-abi/src/pwd_abi.rs crates/frankenlibc-abi/tests/pwd_abi_test.rs`: passed.
- `cargo check -p frankenlibc-abi`: passed on rch (`hz1`) before rebase and
  on the post-rebase tree via rch `ovh-a`; both runs had only unrelated
  pre-existing workspace warnings.
- `cargo test -p frankenlibc-abi --test pwd_abi_test getpwuid_refreshes_cached_uid_after_backend_change`:
  passed on rch (`hz1`) before rebase and on the post-rebase tree via rch
  `vmi1152480`, 1 passed.
- `cargo build -p frankenlibc-abi --release`: passed on the post-rebase tree via
  rch `vmi1152480`, with only unrelated pre-existing warnings.
- `git diff --check HEAD~1..HEAD` and touched-file `rustfmt --check`: passed
  after rebase.

## Verdict

Partial keep. This is a measured deployed ABI improvement on the target loss,
but `getpwuid(0)` still loses p50 against host glibc. Do not retry passwd parser
reshaping or a last-result-only cache. The next attempt should build a
per-generation uid index over a parsed passwd snapshot or share a lower-cost
file-epoch/invalidation primitive with group.
