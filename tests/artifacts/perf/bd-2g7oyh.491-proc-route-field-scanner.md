# bd-2g7oyh.491 - proc route field scanner

## Scope

- Bead: `bd-2g7oyh.491`
- Parent: `bd-2g7oyh`
- Lever: replace `parse_proc_net_route_has_ipv4` split/filter iterator field
  extraction with the existing indexed procfs scanner over the same space/tab
  grammar.
- Bench target: existing `parse_proc_net_route_has_ipv4_typical` in
  `crates/frankenlibc-bench/benches/resolv_parsers_bench.rs`.

## Routing Evidence

`AI_ADDRCONFIG` probes `/proc/net/route` during resolver setup. The flags parser
already moved to a byte-level hex parser in an earlier bead; this batch targets
the remaining fixed-field iterator pipeline without changing the hex semantics.
This is a realistic resolver control path and avoids allocator, stdio, memchr,
memcmp, log2f, and netgroup retry families.

## Behavior Guard

- The field separator remains exactly space or tab.
- The header row is still skipped.
- Missing flags still reject the row.
- Loopback rows are still ignored.
- Trailing fields remain tolerated, matching the previous fixed-prefix parser.
- A non-loopback row returns `true` only when the parsed flags have the UP bit.

## Negative-Evidence Ledger

| Attempt | Status | Evidence |
| --- | --- | --- |
| `split(...).filter(...).next()` route field extraction | Replaced | Correct but pays iterator adapter overhead for a fixed four-field prefix. |
| Reusing the indexed procfs space/tab scanner for the route prefix | Kept for batch testing | Guard added; existing route bench row will classify the timing later. |
| Retrying allocator/calloc, stdio direct-I/O/global-lock, memchr/memcmp/log2f, or netgroup delimiter levers | Avoided | Those lanes are test-capable gated, already owned, or recorded as rejected/noisy in the campaign ledger. |

## Validation

- `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-core`: passed
- Full tests, `rch`, and Criterion: intentionally not run in this code-first batch per campaign instruction.
