# bd-2g7oyh - deployed strtol direct C-string parser

Date: 2026-06-20
Agent: BlackThrush / cod-a
Worker: vmi1152480
Target dir: `/data/projects/.rch-targets/frankenlibc-cod-a`

## Lever

Deploy a base-10/base-16 `strtol` specialization in
`crates/frankenlibc-abi/src/stdlib_abi.rs` that parses the caller's
NUL-terminated C string directly instead of first scanning it into a bounded
slice and then delegating to the generic core parser.

The transducer fuses whitespace/sign handling, optional `0x` prefix handling,
digit scan, overflow cutoff/cutlim, `errno`, and `endptr` cursor accounting.
Other bases remain on the generic path.

## Validation

Formatting:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-abi/src/stdlib_abi.rs
```

Result: passed.

Differential fuzz:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
RCH_WORKER=vmi1152480 RCH_WORKERS=vmi1152480 RCH_PREFERRED_WORKER=vmi1152480 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
AGENT_NAME=BlackThrush CARGO_BUILD_JOBS=1 \
rch exec -- cargo test -p frankenlibc-abi \
  --test strtol_family_differential_fuzz -- --nocapture
```

Result: `strtol family fuzz: 1000000 compared, 0 divergences vs host glibc`.

Benchmark command, run once in the clean baseline worktree at `e464f5c31` and
once in the candidate worktree:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
RCH_WORKER=vmi1152480 RCH_WORKERS=vmi1152480 RCH_PREFERRED_WORKER=vmi1152480 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
AGENT_NAME=BlackThrush CARGO_BUILD_JOBS=1 \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench strtol_glibc_bench -- \
  --measurement-time 2 --warm-up-time 1 --noplot
```

## Results

| Workload | Baseline FL | Baseline glibc | Baseline ratio | Candidate FL | Candidate glibc | Candidate ratio | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| `strtol_dec_short` | 14.21 ns | 8.76 ns | 1.62x | 7.65 ns | 4.82 ns | 1.59x | NEUTRAL gap-cut |
| `strtol_dec_long` | 34.25 ns | 18.07 ns | 1.90x | 22.16 ns | 17.88 ns | 1.24x | WIN gap-cut |
| `strtol_hex` | 37.68 ns | 18.24 ns | 2.07x | 21.38 ns | 18.02 ns | 1.19x | WIN gap-cut |

## Verdict

Keep. `strtol_dec_long` and `strtol_hex` are real same-worker loss reductions,
and the short row is an absolute FL speedup but ratio-neutral because the glibc
denominator also moved in the paired run. This is a parser gap cut, not a
complete domination claim.

Residual route: short `strtol` still needs lower entrypoint/endptr overhead, and
`strtod` remains the next parser-family loss in this bench.
