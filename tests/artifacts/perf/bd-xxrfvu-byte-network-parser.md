# bd-xxrfvu byte network-number parser for NSS `/etc/networks`

Date: 2026-06-18
Agent: BlackThrush / cod-b
Status: code-first batch-test pending

## Target

Profile handoff: `tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`.

Bench target for the later batch gate:

| row | prior p50 ns | prior mean ns | note |
|---|---:|---:|---|
| `parse_networks_line_typical` | 137.8 | 136.9 | single `/etc/networks` line |

The same artifact records the line parser family as mostly allocation plus
validation cost. This bead deliberately avoids the API/lifetime change of
returning borrowed fields and attacks only the numeric validation detour.

## Negative-Evidence Screen

Do not retry these adjacent families without a fresh benchmark and a materially
different primitive:

- `bd-osbo8c`: netgroup throwaway `Vec<&[u8]>` was already fixed.
- `bd-2g7oyh.9`: netgroup first-token early reject already shipped.
- `bd-2g7oyh.99`: netgroup single-pass delimiter parser was proof-clean but slower.
- `bd-9ran7n`: services/protocols decimal fields already have a code-first
  byte parser pending batch classification.

This batch is separate from `bd-9ran7n`: it targets glibc-style
`inet_network` numbers in `/etc/networks`, including decimal, octal, hex, and
partial dotted components.

## Lever

Replace the hot parser path used by `parse_networks_line`:

- before: number bytes -> UTF-8 validation -> `str` split -> component parser;
- after: number bytes -> byte split on `.` -> checked ASCII component parser.

The public `parse_network_number(&str)` API remains as a wrapper over the byte
helper, so callers that already hold text keep the same surface.

This is the graveyard representation-removal primitive: keep the data plane on
raw bytes for an ASCII-only grammar and avoid a redundant representation proof
inside a realistic config-file parser.

## Isomorphism

- Accepted grammar remains non-empty `inet_network` components:
  decimal, octal via leading `0`, hex via `0x`/`0X`, dotted with at most four
  components, each component `<= 0xff`.
- Rejected grammar remains empty, trailing-dot empty components, more than four
  components, signs, out-of-range values, radix-invalid digits, and non-ASCII
  bytes.
- Folding order is unchanged: `result = (result << 8) | component`.
- `parse_networks_line` still strips comments, splits fields, owns the same
  `name` and `aliases`, and returns the same `NetworkEntry` shape.
- Floating-point state, RNG, errno, locale, and allocation behavior outside the
  number token are unchanged.

## Guard

Added unit coverage for:

- byte helper parity on decimal, octal, hex, two-component dotted, and
  full dotted forms;
- empty, trailing-dot, five-component, sign, signed-component, out-of-range,
  and non-UTF-8 rejection;
- `parse_networks_line` rejection of a non-UTF-8 number token.

Existing `parse_network_number` and `parse_networks_line` tests continue to pin
the public `&str` wrapper and line-level behavior.

## Retry-Condition Predicate

Later batch classification must run `resolv_parsers_bench` on the same worker
or a directly comparable target and mark this as:

- keep only if `parse_networks_line_typical` has stable p50/mean
  non-regression and improves enough to clear the campaign score gate;
- reject/revert if the row regresses materially or the improvement stays within
  local variance;
- do not retry `/etc/networks` number parsing unless a different primitive is
  named, such as a borrowed-entry API redesign or a generated parser shared
  across NSS file parsers.

## Validation This Turn

Per campaign instruction, no tests, rch, or benchmarks are run in this batch.
Only:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-core
```

Result is recorded in `bd-xxrfvu` notes after the check.
