# bd-2g7oyh CP932 packed direct decode

Date: 2026-06-20
Agent: BlackThrush
Lane: iconv CP932-family DBCS -> UTF-8 residual after the guard-list fix

## Lever

Japanese CP932-family text is dominated by two-byte DBCS pairs that decode to
BMP scalars whose UTF-8 encoding is always three bytes. The prior generic fast
path still decoded each pair to `char`, then re-encoded through the scalar UTF-8
writer and copied from a stack buffer.

This change adds a lazily-built 65536-entry direct table for CP932, IBM943, and
IBM932:

- key: two-byte DBCS code as `u16`
- value: packed 3-byte UTF-8 triple for U+0800..=U+FFFF, excluding surrogates
- zero sentinel: fall through to the exact generic path

The conversion loop emits four pairs per iteration when input and output space
allow it. Any single-byte character, invalid pair, incomplete lead byte,
surrogate/astral mapping, or short output tail stops before consuming the
problem byte and lets the generic path preserve `EILSEQ`/`EINVAL`/`E2BIG`
ordering.

## Baseline

Command:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_VERBOSE=1 \
RCH_WORKER=hz1 \
RCH_WORKERS=hz1 \
RCH_PREFERRED_WORKER=hz1 \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR,AGENT_NAME \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench iconv_glibc_bench cp932 -- --measurement-time 2 --warm-up-time 1 --noplot
```

Head: `291b3fb0b`
Worker: `hz1`

| Workload | FrankenLibC p50 | FrankenLibC mean | glibc p50 | glibc mean | p50 ratio |
|---|---:|---:|---:|---:|---:|
| `utf8_jp_to_cp932` | 2384.5 ns | 2869.0 ns | 2387.4 ns | 2573.9 ns | 0.999x |
| `cp932_to_utf8` | 27169.4 ns | 25251.8 ns | 482.8 ns | 579.2 ns | 56.27x |

## Final

Command: same as baseline.
Worker: `hz1`

| Workload | FrankenLibC p50 | FrankenLibC mean | glibc p50 | glibc mean | p50 ratio | verdict |
|---|---:|---:|---:|---:|---:|---|
| `utf8_jp_to_cp932` | 2025.2 ns | 2457.7 ns | 2335.7 ns | 2402.5 ns | 0.867x | WIN |
| `cp932_to_utf8` | 509.5 ns | 1229.3 ns | 493.0 ns | 552.6 ns | 1.033x | NEUTRAL |

Final score: 1 win, 0 losses, 1 neutral versus host glibc. The target decode
path improved 53.3x by p50 versus the same-worker baseline and moved from a
56.27x glibc loss to a neutral 1.033x ratio. The mean is noisier because
criterion reported high outliers in the FrankenLibC decode samples; p50 is the
decision metric used by the ledger.

## Validation

Passed:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_VERBOSE=1 \
RCH_WORKER=hz1 \
RCH_WORKERS=hz1 \
RCH_PREFERRED_WORKER=hz1 \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR,AGENT_NAME \
rch exec -- cargo check -p frankenlibc-core
```

Passed:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_VERBOSE=1 \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR,AGENT_NAME \
rch exec -- cargo test -p frankenlibc-abi --test conformance_diff_iconv_cp932 -- --nocapture
```

Result: `cp932_aliases_open`, `cp932_decode_matches_glibc_full_range`, and
`cp932_encode_matches_glibc_full_range` all passed.

Known ambient gate debt, not introduced here:

- `frankenlibc-core` emits pre-existing warnings in iconv and string regex code.
- `frankenlibc-abi` emits pre-existing warning debt while building the ABI bench.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/iconv/mod.rs`
  fails because the existing generated/monolithic iconv file is already outside
  rustfmt shape and rustfmt wants broad unrelated churn.

## Stop rule

Keep this lever. Do not retry another scalar per-pair arithmetic rewrite on this
surface. A future CP932 residual attempt should first prove a stable post-table
loss on the same worker, then target a genuinely different shape such as a wider
vectorized DBCS validity/table-probe front end.
