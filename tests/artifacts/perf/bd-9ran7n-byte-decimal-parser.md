# bd-9ran7n byte decimal parser for NSS service/protocol rows

Date: 2026-06-18
Agent: BlackThrush / cod-b
Status: MEASURED KEEP (2026-06-19)

## Target

Profile handoff: `tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`.

Bench targets for the later batch gate:

| row | prior p50 ns | prior mean ns | note |
|---|---:|---:|---|
| `parse_protocols_line_typical` | 99.3 | 101.0 | single `/etc/protocols` line |
| `parse_services_line_typical` | 134.0 | 136.3 | single `/etc/services` line |

## Negative-Evidence Screen

Do not retry these adjacent families without a fresh benchmark and a materially
different primitive:

- `bd-osbo8c`: netgroup throwaway `Vec<&[u8]>` was already fixed.
- `bd-2g7oyh.9`: netgroup first-token early reject already shipped.
- `bd-2g7oyh.99`: netgroup single-pass delimiter parser was proof-clean but slower.
- `bd-yftnsz`: printf segment `Vec` allocation already shipped via small inline storage.

This batch deliberately avoids netgroup and printf. It targets the simpler
ASCII decimal fields in `/etc/services` and `/etc/protocols`.

## Lever

Replace the decimal helper used by `parse_services_line` and
`parse_protocols_line`:

- before: field bytes -> UTF-8 validation -> `str::parse::<u32>()`;
- after: direct safe byte loop over ASCII digits with `u32` checked arithmetic.

This is the buried-CS/vectorization-lite pattern from the graveyard search:
remove avoidable representation conversion in a hot byte parser and keep the
data plane on raw bytes. The proof artifact is an explicit parser contract
rather than a new runtime controller.

## Isomorphism

- Accepted grammar: non-empty ASCII decimal digits only.
- Rejected grammar: empty, sign-prefixed, non-digit, non-UTF-8, and overflowing
  fields still reject.
- `parse_services_line` still bounds the accepted value to `u16`.
- `parse_protocols_line` still bounds the accepted value to `i32`.
- Comment stripping, whitespace splitting, alias ownership, output order, errno,
  allocation shape outside the decimal helper, floating-point state, and RNG are
  unchanged.

## Guard

Added unit coverage for:

- `0`, ordinary positive values, and `u32::MAX`;
- empty field;
- `+` / `-` signs;
- embedded non-digit slash;
- `u32::MAX + 1` overflow;
- non-UTF-8 bytes.

Existing service/protocol parser tests cover line-level behavior, including
signed rejection and protocol separator rejection.

## Measured Head-to-Head Result

Batch classification was upgraded from parser-only pending to deployed ABI
head-to-head evidence vs host glibc:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b/criterion-bd-9ran7n-20260619T0341 \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- \
  glibc_baseline_resolv_services_protocols --noplot \
  --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Worker: `hz1`.

| row | FrankenLibC p50 | glibc p50 | p50 ratio | FrankenLibC mean | glibc mean | mean ratio | verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| `getservbyname("http","tcp")` | 28.532 us | 435.582 us | 0.0655x | 29.085 us | 420.606 us | 0.0692x | WIN |
| `getprotobyname("tcp")` | 125.854 us | 129.508 us | 0.9718x | 126.718 us | 131.459 us | 0.9639x | NEUTRAL |

Classification: **keep**. The service lookup is a large deployed ABI win, and
the protocol lookup is neutral/slightly faster rather than a regression.

## Validation

Compiler/bench harness:

- `cargo check -p frankenlibc-bench --features abi-bench --bench glibc_baseline_bench`: passed.

Core parser guards:

- `cargo test -p frankenlibc-core resolv::tests::decimal_u32_byte_parser_rejects_signs_non_digits_and_overflow -- --nocapture`: passed.
- `cargo test -p frankenlibc-core resolv::tests::parse_services -- --nocapture`: 7 passed.
- `cargo test -p frankenlibc-core resolv::tests::protocol_ -- --nocapture`: 11 passed.

ABI differential guards:

- `cargo test -p frankenlibc-abi --test conformance_diff_netdb_aliases -- --nocapture`: passed.
- `cargo test -p frankenlibc-abi --test conformance_diff_protoent_r_aliases -- --nocapture`: passed.
- `cargo test -p frankenlibc-abi --test conformance_diff_netdb_r_aliases -- --nocapture`: passed.

Known caveats:

- These commands emit pre-existing warning debt in iconv/math/poll/signal
  tables; no new warning is attributable to this resolver parser lever.
- `cargo fmt --check -p frankenlibc-bench` is blocked by pre-existing formatting
  drift in existing bench files. I did not normalize those files because that
  would stage unrelated churn.
- `cargo clippy -p frankenlibc-bench --features abi-bench --bench glibc_baseline_bench -- -D warnings`
  is blocked before bench linting by pre-existing `frankenlibc-core` lint debt
  in iconv/resolv/printf modules.

## Retry-Condition Predicate

Do not revisit byte-decimal parsing for resolver rows unless a future same-worker
deployed ABI run shows a material regression. The next resolver/NSS performance
work should target a different parser, database-scan, or caching primitive with
its own head-to-head proof.
