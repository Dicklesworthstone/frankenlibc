# bd-2g7oyh.502: strict inet_ntop(AF_INET) ABI fast path

Date: 2026-06-21
Assignee: cod-a / BlackThrush

## Lever

`inet_ntop(AF_INET)` was dominated by strict-mode runtime policy overhead plus a
stack-buffer formatting path. In strict mode, `ApiFamily::Inet` policy
`decide()` is forced `Allow` and non-adverse `observe()` is telemetry-only, so
the IPv4 ABI call can safely use a strict-only fast path:

- null `src`/`dst` still returns null and sets `EFAULT`
- unsupported families still use the existing full path and set `EAFNOSUPPORT`
- undersized caller buffers still return null and set `ENOSPC`
- IPv4 text formatting writes directly into the caller buffer
- hardened mode and non-IPv4 calls retain the full tracked-region path

The final variant removes tracked-region membership checks from the strict
IPv4 hot path. Those checks remain in the full path and in hardened mode.

## Benchmarks

Command shape:

```bash
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench inet_ntop_glibc_bench --profile release -- --noplot \
  --sample-size 20 --warm-up-time 0.5 --measurement-time 1
```

Baseline routing, before edit, worker `ovh-a`:

- frankenlibc ABI: 104.78 ns
- host glibc: 9.1629 ns
- ratio: 11.44x LOSS

First tracked-region fast path, worker `ovh-a`:

- frankenlibc ABI: 14.634 ns
- host glibc: 9.2918 ns
- ratio: 1.575x LOSS
- self-speedup vs original frankenlibc baseline: 7.16x

Intermediate fixed-buffer run, worker `hz1`:

- frankenlibc ABI: 25.450 ns
- host glibc: 18.257 ns
- ratio: 1.394x LOSS

Final strict raw-buffer run, worker `vmi1293453`:

- frankenlibc ABI: 20.663 ns, CI [19.992 ns, 21.760 ns]
- host glibc: 22.710 ns, CI [20.365 ns, 25.650 ns]
- ratio: 0.91x WIN

## Validation

```bash
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo check -j 1 -p frankenlibc-core --release

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo check -j 1 -p frankenlibc-abi --release

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo test -j 1 -p frankenlibc-core inet_ntop --release

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo test -j 1 -p frankenlibc-abi --test inet_abi_test inet_ntop --release

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo test -j 1 -p frankenlibc-abi --test conformance_diff_arpa_inet diff_inet_ntop --release

git diff --check
```

Results:

- `frankenlibc-core` release check: PASS, with pre-existing warnings.
- `frankenlibc-abi` release check: PASS, with pre-existing warnings.
- Core `inet_ntop` focused tests: PASS, 3 unit tests plus `inet_ntop_differential_battery`.
- ABI `inet_ntop` focused test: PASS, 7 passed / 2 ignored.
- ABI conformance diff: PASS, `diff_inet_ntop_v4_roundtrip` and `diff_inet_ntop_v6_roundtrip`.
- `git diff --check`: PASS.
- `rustfmt --check` on touched files is blocked by pre-existing formatting drift in unchanged sections of `inet/mod.rs` and `inet_abi.rs`; no whitespace errors were introduced.
