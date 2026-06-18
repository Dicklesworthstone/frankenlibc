# bd-2g7oyh.483: /etc/gshadow single-pass colon-tail parser

## Bead

- `bd-2g7oyh.483`
- Title: `perf: single-pass /etc/gshadow colon-tail parser`
- Assignee: `cod-b`
- Status after this batch: `in_progress`

## Routing Evidence

- Source profile family: `tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`
- Adjacent live parser rows in `resolv_parsers_bench`: `parse_hosts_line_typical`,
  `parse_services_line_typical`, `parse_protocols_line_typical`,
  `parse_networks_line_typical`, `parse_aliases_line_typical`,
  `parse_passwd_line_typical`.
- Recent same-family code-first leaves removed temporary field vectors, UTF-8
  numeric parsing, or tail rebuilds from `/etc` parser paths. `gshadow` still
  had the colon-field `Vec<&[u8]>` plus `fields[3..].join(b":")` tail rebuild.

## Lever

`parse_gshadow_line` previously:

1. split the whole line and collected every colon-delimited field into a
   temporary `Vec<&[u8]>`;
2. copied `fields[1]` and `fields[2]` for password/admin lists;
3. rebuilt the member tail with `fields[3..].join(b":")` so extra colons were
   preserved.

This batch replaces the collect/join path with `splitn(4, b':')`. The parser
now scans only through the third colon, borrows the absorbed member tail, and
only allocates the four owned output fields required by `Gshadow`.

## Behavior Guard

Existing inline tests already cover full lines, minimal `root:*::`, empty and
locked passwords, admin/member fields, short lines, extra colon absorption,
empty-name rejection, comments, blank lines, CRLF trimming, lookup behavior, and
case sensitivity.

Added guard:

- `splitn_scanner_preserves_short_lines_and_tail` proves one-field gshadow
  lines still default optional fields to empty, `wheel:::` keeps empty optional
  fields empty, and the fourth split field still absorbs all remaining colons.

## Negative-Evidence Ledger

| Attempt family | Evidence | Batch decision |
| --- | --- | --- |
| `memchr_absent` panel/width/SWAR retunes | Prior focused ledgers rejected or routed these families; memory forbids retrying without a new generated primitive. | Not retried. |
| `memcmp_*` surface loop retunes | Prior same-worker gates rejected shallow equality-loop variants. | Not retried. |
| `malloc_free_256` hot-list/slab micro retunes | Prior focused gates rejected or found the allocator lane needs deeper/test-capable work. | Not retried. |
| `log2f` exponent/atanh extraction | Prior math ledgers rejected correctness/perf variants. | Not retried. |
| `parse_group_line` colon-tail splitn | Already landed as `bd-2g7oyh.481`; this bead applies the same allocation-removal shape to the distinct gshadow parser. | Not duplicated. |
| `parse_passwd_line` field scanner | Already landed as `bd-2g7oyh.482` by a swarm mate before this turn. | Not duplicated. |
| `calloc` fresh-mmap zero skip and `fwrite` direct bypass | `bv` surfaced these, but both are assigned to `cc` and documented as test-capable turns, not cargo-check-only leaves. | Not claimed. |
| `parse_gshadow_line` colon-field Vec plus tail join removal | This batch. | Pending focused benchmark verdict. |

## Validation

Campaign instruction for this batch permits only:

```text
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-core
```

No test, rch, criterion benchmark, or conformance run is performed in this
code-first batch.

Result:

- PASS: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b AGENT_NAME=BlackThrush cargo check -p frankenlibc-core`
- Existing unrelated output remained: no SMT solver notice for generated stdio
  table proof, plus iconv warnings for `emit_g1` unused `mut` and unused
  `EUCJX_P2_MULTI`.

## Keep / Reject Rule For Batch Validation

Keep only if a later same-worker benchmark adds or runs a
`parse_gshadow_line_typical` row and shows improvement without any gshadow
parser conformance/unit regression. Reject and revert or route deeper if the
row is neutral/slower, if the effect is noise, or if any parser behavior
diverges.
