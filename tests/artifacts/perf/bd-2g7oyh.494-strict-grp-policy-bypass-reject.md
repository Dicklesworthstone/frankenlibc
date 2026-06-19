# bd-2g7oyh.494 strict grp runtime-policy bypass reject

Bead: `bd-2g7oyh.494` (`perf: build group gid snapshot index for residual getgrgid p50 gap`)

Candidate tested: strict-mode `getgrnam` / `getgrgid` bypasses the resolver
runtime-policy `decide` / `observe` path after resolving `FRANKENLIBC_MODE`
through `runtime_policy::mode()`. Hardened mode kept the existing policy gate.

Alien lever mapping: RCU/immutable-read-path principle for read-mostly NSS
metadata, but applied at the ABI policy layer rather than the parsed group
snapshot because the repeated `getgrgid(0)` benchmark is not varied-GID-index
limited.

## Decision

**Rejected / not landed.** The candidate produced a fast same-run win vs glibc,
but did not get acceptance-grade same-worker `HEAD` vs candidate proof. The
completed clean `HEAD` baseline routed to `vmi1153651`; the completed candidate
routed to `vmi1293453`; the attempted same-path `HEAD` baseline on
`vmi1167313` hung after Criterion analysis and before structured FL/host
output; the immediate candidate rerun then routed to `ovh-b`.

No source code from this candidate is kept in `main`.

## Commands

Clean `HEAD` baseline, scratch worktree
`/data/projects/.scratch/frankenlibc-bd-2g7oyh-494-c08ab1f8` at `c08ab1f8d`:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR \
rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench \
  --features abi-bench -- getgrgid_0 --sample-size 10 --warm-up-time 1 \
  --measurement-time 2
```

Candidate used the same command after applying the strict `grp` policy bypass
in the scratch worktree.

## Completed Runs

| Run | Worker | fl p50 | glibc p50 | ratio | Verdict |
|---|---|---:|---:|---:|---|
| Clean `HEAD` baseline | `vmi1153651` | 14,254.555 ns | 16,751.465 ns | 0.851x | WIN vs glibc; no residual loss reproduced |
| Candidate strict `grp` policy bypass | `vmi1293453` | 9,830.743 ns | 11,091.367 ns | 0.886x | WIN vs glibc; cross-worker only vs baseline |

Non-acceptance attempts:

- Clean `HEAD` same-path attempt on `vmi1167313`: Criterion printed
  `getgrgid_0/frankenlibc_abi time [13.797 us 14.130 us 14.604 us]`, then
  stalled before the structured summary and before host glibc. Stopped with
  Ctrl-C; not counted as final evidence.
- Immediate candidate rerun selected `ovh-b`, not `vmi1167313`; stopped before
  benchmark execution because it could not serve as a same-worker comparison.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-abi/src/grp_abi.rs`:
  passed in the candidate scratch worktree.
- Broad `cargo test -p frankenlibc-abi grp_abi` was not usable as a focused
  signal: it attempted all ABI integration tests and hit the existing
  `conformance_diff_crypt_failure_token` undefined `crypt` link failure.
- No candidate source was landed, so final source validation for `main` is the
  artifact/ledger-only diff plus tracker state.

## Negative Evidence / Retry Predicate

Do not land or retry this strict `grp` policy bypass based on cross-worker
absolute latency. Return only with one of:

- a same-worker completed `HEAD` vs candidate pair, or
- a direct harness that builds both baseline and candidate in the same process
  or on a pinned worker, with `getgrgid_0` p50 and ratio-vs-glibc both improved.

Do not retry default-source-only stat/env bypasses; those were rejected in
`bd-2g7oyh.493`.
