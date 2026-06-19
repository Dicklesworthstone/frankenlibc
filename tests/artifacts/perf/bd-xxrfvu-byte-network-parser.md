# bd-xxrfvu byte network-number parser for NSS `/etc/networks`

Date: 2026-06-19
Agent: BlackThrush / cod-a
Status: measured keep

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

## BOLD-VERIFY Same-Worker Gate

The code-first lever was measured head-to-head against its parent commit using
the same rch worker. This is internal old-vs-new parser evidence, not a
host-glibc comparator.

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_VERBOSE=1 \
FRANKENLIBC_RESOLV_BENCH_MODE=strict \
rch exec -- cargo bench -p frankenlibc-bench --bench resolv_parsers_bench --profile release
```

- Worker: `vmi1153651` (`root@38.242.134.66`) for both baseline and
  candidate.
- Baseline worktree:
  `/data/projects/.scratch/frankenlibc-cod-a-bdxxrfvu-baseline-20260619T180525Z`
  at `db8919ba3^` (`e79873169`).
- Candidate worktree:
  `/data/projects/.scratch/frankenlibc-cod-a-bdxxrfvu-candidate-20260619T180525Z`
  at `db8919ba3`.
- Focused row: `parse_networks_line_typical`.

| Metric | Baseline UTF-8 + str split | Candidate byte parser | Candidate / baseline |
|---|---:|---:|---:|
| p50 ns/op | 243.090 | 195.091 | 0.803x |
| mean ns/op | 446.336 | 223.541 | 0.501x |
| p95 ns/op | 1603.047 | 230.951 | 0.144x |
| p99 ns/op | 3399.881 | 761.473 | 0.224x |
| throughput ops/s | 2,240,464.663 | 4,473,445.794 | 1.997x |

Verdict: **WIN / keep**. The candidate improves p50 by 19.7%, halves mean
latency, and almost doubles throughput on the same worker. No source revert.
This bead's measured win/loss/neutral count is `1 / 0 / 0`.

## Validation This Turn

- `rustfmt --check --edition 2024 crates/frankenlibc-core/src/resolv/mod.rs`:
  passed.
- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo test -p frankenlibc-core netnum --lib -- --nocapture`:
  12 passed, 0 failed, 3167 filtered.
- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo test -p frankenlibc-core network_ --lib -- --nocapture`:
  15 passed, 0 failed, 3164 filtered.
- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-core`:
  passed with the existing unrelated iconv warnings and the known missing SMT
  solver notice.

An initial `parse_network` test filter matched zero tests and is not counted as
coverage evidence.
