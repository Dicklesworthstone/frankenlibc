# bd-9ran7n byte decimal parser for NSS service/protocol rows

Date: 2026-06-18
Agent: BlackThrush / cod-b
Status: code-first batch-test pending

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

## Retry-Condition Predicate

Later batch classification must run `resolv_parsers_bench` on the same worker or
a directly comparable target and mark this as:

- keep only if both `parse_protocols_line_typical` and
  `parse_services_line_typical` have stable p50/mean non-regression and at
  least one row improves enough to clear the campaign score gate;
- reject/revert if either row regresses materially or the improvement is within
  the local variance envelope;
- continue only with a different parser primitive if this lands flat.

## Validation This Turn

Per campaign instruction, no tests, rch, or benchmarks are run in this batch.
Only:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-core
```

Result is recorded in `bd-9ran7n` notes after the check.
