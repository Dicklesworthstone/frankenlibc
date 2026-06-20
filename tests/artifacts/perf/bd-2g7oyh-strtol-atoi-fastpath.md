# bd-2g7oyh - deployed ato* single-pass fast path

Date: 2026-06-20
Agent: BlackThrush / cod-a

## Target

Fresh deployed `strtol_glibc_bench` coverage showed `atoi`, `atol`, and
`atoll` were still paying the generic membrane/scan/parse shape even though
their contract is narrower than `strtol`: base-10 only and no end pointer.

The kept lever is a deployed-only direct decimal parser for `atoi` and `atol`;
`atoll` delegates to `atol`, so it benefits from the same path. Test builds keep
the existing full membrane route.

## Bench Method

Baseline and candidate were both run on `vmi1149989` using the per-crate bench:

```text
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench strtol_glibc_bench -- --noplot
```

The glibc arm resolves host symbols with `dlmopen(LM_ID_NEWLM)`, so the benchmark
does not interpose FrankenLibC symbols over the host denominator.

## Same-Worker Baseline

Baseline worktree: `72ebe242c` plus benchmark-only `ato*` rows, no source lever.
Worker: `vmi1149989`.

| Row | FrankenLibC | glibc | FL/glibc | Verdict |
|---|---:|---:|---:|---|
| `strtol_dec_short` | 19.18 ns | 8.43 ns | 2.28x | LOSS |
| `strtol_dec_long` | 35.96 ns | 15.91 ns | 2.26x | LOSS |
| `strtol_hex` | 37.81 ns | 19.64 ns | 1.92x | LOSS |
| `atoi_short` | 31.56 ns | 11.10 ns | 2.84x | LOSS |
| `atoi_long` | 37.19 ns | 10.83 ns | 3.43x | LOSS |
| `atol_short` | 28.66 ns | 9.27 ns | 3.09x | LOSS |
| `atol_long` | 41.88 ns | 16.50 ns | 2.54x | LOSS |
| `atoll_short` | 28.46 ns | 9.64 ns | 2.95x | LOSS |
| `atoll_long` | 28.99 ns | 10.37 ns | 2.80x | LOSS |
| `strtod_int` | 38.30 ns | 31.16 ns | 1.23x | LOSS |
| `strtod_simple` | 36.01 ns | 41.75 ns | 0.86x | WIN |
| `strtod_sci` | 39.63 ns | 28.54 ns | 1.39x | LOSS |

## Candidate Proof

Final clean post-rebase candidate worker: `vmi1149989`. This rerun happened
after rebasing over `4ed56fd05`, which had already added a weaker membrane fast
path for `ato*`; the direct parser still wins versus host glibc on every row.

| Row | FrankenLibC | glibc | FL/glibc | Candidate/Baseline FL | Verdict |
|---|---:|---:|---:|---:|---|
| `atoi_short` | 2.97 ns | 5.25 ns | 0.57x | 0.094x | WIN |
| `atoi_long` | 7.51 ns | 14.67 ns | 0.51x | 0.202x | WIN |
| `atol_short` | 2.80 ns | 4.91 ns | 0.57x | 0.098x | WIN |
| `atol_long` | 9.31 ns | 10.77 ns | 0.87x | 0.222x | WIN |
| `atoll_short` | 2.53 ns | 4.92 ns | 0.52x | 0.089x | WIN |
| `atoll_long` | 7.57 ns | 10.99 ns | 0.69x | 0.261x | WIN |

The kept surface moves from `2.54x-3.43x` slower than glibc to `0.51x-0.87x`
of glibc, a `3.8x-11.2x` FrankenLibC self-speedup versus the original
same-worker baseline.

Unchanged rows in the same candidate run are not credited to this lever. The
`strtol_*` rows and two `strtod_*` rows remain residual losses; `strtod_simple`
is an unrelated win.

| Row | FrankenLibC | glibc | FL/glibc | Verdict |
|---|---:|---:|---:|---|
| `strtol_dec_short` | 26.63 ns | 8.57 ns | 3.11x | LOSS |
| `strtol_dec_long` | 36.47 ns | 16.51 ns | 2.21x | LOSS |
| `strtol_hex` | 26.63 ns | 12.98 ns | 2.05x | LOSS |
| `strtod_int` | 24.33 ns | 17.73 ns | 1.37x | LOSS |
| `strtod_simple` | 31.58 ns | 40.17 ns | 0.79x | WIN |
| `strtod_sci` | 45.34 ns | 26.84 ns | 1.69x | LOSS |

Follow-up route: `strtol`/`strtod` still need deeper single-pass parser work.
This `ato*` lever does not claim those rows.

## Validation

All current-file validation passed:

```text
rustfmt --edition 2024 --check \
  crates/frankenlibc-abi/src/stdlib_abi.rs \
  crates/frankenlibc-abi/tests/strict_mode_refinement_test.rs \
  crates/frankenlibc-bench/benches/strtol_glibc_bench.rs

git diff --check

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 rch exec -- \
  cargo test -p frankenlibc-abi --test strict_mode_refinement_test refinement_ -- --nocapture
# vmi1152480: 16 passed, 0 failed, 2 filtered out

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 rch exec -- \
  cargo test -p frankenlibc-abi --test strtol_family_differential_fuzz -- --nocapture
# hz2: 1,000,000 compared, 0 divergences vs host glibc

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 rch exec -- cargo build -p frankenlibc-abi --release
# vmi1227854: passed
```

Post-rebase confirmation:

```text
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 rch exec -- \
  cargo test -p frankenlibc-abi --test strict_mode_refinement_test refinement_ -- --nocapture
# vmi1293453: 16 passed, 0 failed, 2 filtered out

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 rch exec -- cargo build -p frankenlibc-abi --release
# vmi1167313: passed

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 rch exec -- cargo bench -p frankenlibc-bench \
  --features abi-bench --bench strtol_glibc_bench -- --noplot
# vmi1149989: clean post-rebase bench rows shown above

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo test -p frankenlibc-abi \
  --test strtol_family_differential_fuzz -- --nocapture
# rch local fallback after remote-only retries hit critical_pressure:
# 1,000,000 compared, 0 divergences vs host glibc
```

Existing warning debt from unrelated ABI/math/iconv modules was emitted during
the remote gates and was not touched by this lever.
