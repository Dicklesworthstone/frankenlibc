# bd-2g7oyh.481: /etc/group single-pass colon-tail parser

## Bead

- `bd-2g7oyh.481`
- Title: `perf: single-pass /etc/group colon-tail parser`
- Assignee: `cod-b`
- Status after this batch: `in_progress`

## Routing Evidence

- Source profile: `tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`
- Adjacent realistic parser rows: `parse_protocols_line_typical` p50 `99.3 ns`,
  `parse_hosts_line_typical` p50 `114.4 ns`, `parse_aliases_line_typical` p50
  `116.8 ns`, `parse_services_line_typical` p50 `134.0 ns`,
  `parse_networks_line_typical` p50 `137.8 ns`.
- Ledger signal: the `/etc` parser family repeatedly pays owned field copies
  and parser allocation cost in real-world config-line workloads.

## Lever

`parse_group_line` previously:

1. collected every colon-delimited field into `Vec<&[u8]>`;
2. joined every field after `gid` back into a fresh `Vec<u8>` so glibc-style
   member tails with extra colons could be represented;
3. comma-split that joined buffer into owned member tokens.

This batch replaces the first two steps with `splitn(4, b':')`, so the parser
scans only through the third colon and keeps the member tail borrowed. The
required owned output fields are unchanged.

## Behavior Guard

Existing inline group tests already cover blank/comment rejection, too few
fields, empty names, optional member list, CRLF trimming, large `gid`, leading
`+` in `gid`, duplicate lookup order, and empty comma-token filtering.

Added guard:

- `extra_colon_tail_preserves_empty_member_filtering` proves the borrowed member
  tail still absorbs extra colons and still drops leading, doubled, and trailing
  empty comma tokens.

## Negative-Evidence Ledger

| Attempt family | Evidence | Batch decision |
| --- | --- | --- |
| `memchr_absent` panel/width/SWAR retunes | Prior same-worker ledgers marked these as no-ship or routing-only; memory notes forbid repeating this family without a new primitive. | Not retried. |
| `memcmp_*` generated/surface loop retunes | Prior focused gates rejected or routed away from surface loop families. | Not retried. |
| `malloc_free_256` hot-list/slab micro retunes | Prior focused gates rejected or blocked; not a group parser workload. | Not retried. |
| `log2f` exponent/atanh extraction | Prior math gate rejected correctness/perf variants. | Not retried. |
| `netgroup` single-pass delimiter parser | Prior same-worker gate rejected the deeper delimiter rewrite. | Not retried. |
| `parse_services_line` / `parse_protocols_line` decimal byte parse | Already landed under `bd-9ran7n`, batch verdict pending. | Not touched. |
| `parse_networks_line` byte numeric parse | Already landed under `bd-xxrfvu`, batch verdict pending. | Not touched. |
| `parse_hosts_line` IPv4 byte validation | Already landed under `bd-43e21q`, batch verdict pending. | Not touched. |
| `parse_aliases_line` member scanner | Already landed under `bd-4crkqx`, batch verdict pending. | Not touched. |
| `parse_group_line` colon-field Vec plus tail join removal | This batch. | Pending focused benchmark verdict. |

## Validation

Campaign instruction for this batch permits only:

```text
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-core
```

No test, rch, criterion benchmark, or conformance run is performed in this
code-first batch.

Result:

- PASS: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-core`
- Existing unrelated warnings remained in `iconv`: `emit_g1` does not need
  `mut`, and `EUCJX_P2_MULTI` is unused.

## Keep / Reject Rule For Batch Validation

Keep only if a later focused benchmark on the same comparable worker shows the
group parser row improves and the group parser conformance/unit guard remains
green. Reject and revert or route deeper if the row is neutral/slower, if this
change is lost in noise, or if any parser behavior diverges.
