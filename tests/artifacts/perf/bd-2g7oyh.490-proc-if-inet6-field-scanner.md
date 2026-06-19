# bd-2g7oyh.490 - proc if_inet6 field scanner

## Scope

- Bead: `bd-2g7oyh.490`
- Parent: `bd-2g7oyh`
- Lever: replace `parse_proc_net_if_inet6_has_ipv6` split/filter iterator field
  extraction with an indexed byte-field scanner over the same space/tab grammar.
- Bench target: `parse_proc_net_if_inet6_has_ipv6_typical` in
  `crates/frankenlibc-bench/benches/resolv_parsers_bench.rs`.

## Routing Evidence

`AI_ADDRCONFIG` probes `/proc/net/if_inet6` during resolver setup. This is a
real resolver control-path workload and the IPv6 sibling of the already-routed
`/proc/net/route` parser work. The change attacks iterator adapter overhead
without touching allocator, printf, memchr, or netgroup families already marked
as saturated, noisy, or actively owned.

## Behavior Guard

- The field separator remains exactly space or tab.
- Rows still require six fields and reject a seventh nonempty field.
- Address fields still require exactly 32 ASCII hex bytes.
- `ifindex`, `prefix_len`, `scope`, and `flags` still require nonempty ASCII hex.
- `lo` rows are skipped; the first valid non-`lo` row returns `true`.

## Negative-Evidence Ledger

| Attempt | Status | Evidence |
| --- | --- | --- |
| `split(...).filter(...).next()` field extraction in `parse_proc_net_if_inet6_has_ipv6` | Replaced | Correct but builds an iterator pipeline and repeatedly advances it for a fixed six-field procfs row shape. |
| Indexed space/tab procfs scanner for fixed six-field rows | Kept for batch testing | Code-first guard and bench row added; crate checks pending in this batch. |
| Retrying allocator/calloc, stdio global-lock/direct-I/O, memchr/memcmp/log2f, or netgroup delimiter levers | Avoided | Those lanes are either test-capable gated, already owned, or recorded as rejected/noisy in the campaign ledger. |

## Validation

- `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-core`: passed
- `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-bench --bench resolv_parsers_bench`: passed
- Full tests, `rch`, and Criterion: intentionally not run in this code-first batch per campaign instruction.
