# bd-li0so3: `/etc/hosts` hostname field scanner

## Bead

- `bd-li0so3`
- Title: `perf: single-pass /etc/hosts hostname field scanner`
- Assignee: `cod-b`
- Status after this batch: `in_progress`

## Routing Evidence

- Source profile: `tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`
- Bench row: `parse_hosts_line_typical`
- Baseline in artifact: p50 `114.4 ns/op`, mean `116.5 ns/op`
- Workload line: `127.0.0.1   localhost localhost.localdomain`

## Lever

`parse_hosts_line` no longer drives the hot row through
`split(...).filter(...).collect()` before address validation. It now uses a
small byte-field scanner to capture the first field, validates the address
before allocating hostname vectors, and then pushes remaining fields in input
order with a small common-case reserve.

Expected benefit if the compiler did not already recover this shape:

- one less generic split/filter/collect state machine in the common parser row;
- invalid first fields reject before allocating hostname `Vec`s;
- common one- or two-hostname rows reserve once instead of growing from zero.

## Behavior Guard

Added `parse_hosts_field_scanner_preserves_comments_and_empty_fields`, covering:

- leading whitespace before the address;
- mixed space/tab runs between fields;
- inline comment termination;
- rows with no hostname before the comment;
- malformed first fields with otherwise valid-looking hostnames.

Existing hosts parser conformance/fuzz tables still pin IPv4, IPv6, comments,
blank rows, CRLF, lookup behavior, and output-substring invariants.

## Negative-Evidence Ledger

| Attempt family | Evidence | Batch decision |
| --- | --- | --- |
| `memchr_absent` panel/width/SWAR retunes | Prior same-worker ledgers marked panel-width and folded-probe families as no-ship. | Not retried. |
| `memcmp_*` load-port/surface retunes | Prior focused gates rejected shallow loop retunes. | Not retried. |
| `malloc_free_256` hot-list/slab micro retunes | Prior focused gates rejected or blocked nearby allocator micro-levers. | Not retried. |
| `log2f` exponent/atanh extraction | Prior math gate rejected the nearby series/exponent family. | Not retried. |
| `netgroup` delimiter/single-pass parser | Prior parser-family delimiter attempt was proof-clean but slower. | Not retried. |
| `parse_services_line` / `parse_protocols_line` decimal byte parse | Already landed under `bd-9ran7n`, batch verdict pending. | Not touched. |
| `parse_networks_line` byte numeric parse | Already landed under `bd-xxrfvu`, batch verdict pending. | Not touched. |
| `parse_hosts_line` IPv4 byte validation | Already landed under `bd-43e21q`, batch verdict pending. | Not duplicated. |
| `parse_hosts_line` hostname split/filter/collect removal | This batch. | Pending focused Criterion/custom-bench verdict. |

## Keep / Reject Rule For Batch Validation

Keep only if the later focused benchmark on the same comparable worker shows
`parse_hosts_line_typical` improves without any hosts parser conformance
regression. Reject and revert/route deeper if the row is neutral/slower or if
any hosts parser behavior diverges from the inline guards.

## Local Validation

- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b AGENT_NAME=BlackThrush cargo check -p frankenlibc-core`
  passed.
- Existing unrelated warnings remained in iconv (`unused_mut` in `emit_g1`,
  unused `EUCJX_P2_MULTI`) plus the missing-SMT-solver notice.
- Per campaign instruction, no tests, `rch`, or benchmark command was run in
  this code-first turn.
