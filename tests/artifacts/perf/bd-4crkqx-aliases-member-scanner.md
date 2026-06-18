# bd-4crkqx: `/etc/aliases` single-pass member scanner

## Bead

- `bd-4crkqx`
- Title: `perf: single-pass aliases member scanner`
- Assignee: `cod-b`
- Status after this batch: `in_progress`

## Routing Evidence

- Source profile: `tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`
- Bench row: `parse_aliases_line_typical`
- Baseline in artifact: p50 `116.8 ns/op`, mean `119.7 ns/op`
- Workload line: `postmaster: root, admin, oncall@example.com`

## Lever

Replace the `rest.split(',').filter_map(...).collect()` member parser with a
manual byte-range scanner and fuse comment/colon discovery into one scan before
trailing whitespace trim.

Expected benefit if the compiler does not already recover this shape:

- one fewer full-line scan on the common non-comment path;
- no generic split/filter/collect state machine on comma-separated members;
- no member-vector allocation for `x:` / whitespace-only member lists;
- first real member reserves the common small aliases capacity once.

## Behavior Guard

Existing inline aliases tests cover:

- blank and comment-only lines;
- missing colon and empty names;
- member whitespace trimming;
- empty member filtering;
- no-member rows;
- CRLF trimming;
- lookup and parse-all behavior.

Added guard:

- `parse_filters_whitespace_only_members` checks whitespace-only comma fields
  stay filtered after the manual scanner.

No benchmark, unit test, rch, or conformance command was run in this code-first
batch per campaign instruction. The local gate is restricted to:

```text
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-core
```

First result in the shared checkout: blocked by unrelated peer-owned local dirt
in `crates/frankenlibc-core/src/stdio/printf.rs` where `#[derive(Debug, Clone)]`
was attached to `INLINE_SEGMENTS` instead of a struct/enum/union. The alias
parser itself was the only core source file touched by this bead.

Rerun after the peer printf/string changes landed cleanly: PASS. Existing
warnings remained in iconv (`unused_mut` in `emit_g1`, unused
`EUCJX_P2_MULTI`) and are unrelated to this aliases bead.

## Negative-Evidence Ledger

| Attempt family | Evidence | Batch decision |
| --- | --- | --- |
| `memchr_absent` panel/width/SWAR retunes | Prior same-worker ledgers marked these as no-ship or routing-only; memory notes forbid repeating this family without a new primitive. | Not retried. |
| `memcmp_*` generated/surface loop retunes | Prior focused gates rejected or routed away from surface loop families. | Not retried. |
| `malloc_free_256` hot-list/slab micro retunes | Prior focused gates rejected/blocked; not an alias parser workload. | Not retried. |
| `log2f` exponent/atanh extraction | Prior math gate rejected correctness/perf variants. | Not retried. |
| `netgroup` delimiter/single-pass parser | Previous parser-family single-pass delimiter attempt was proof-clean but slower. | Not retried. |
| `parse_services_line` / `parse_protocols_line` decimal byte parse | Already landed under `bd-9ran7n`, batch verdict pending. | Not touched. |
| `parse_networks_line` byte numeric parse | Already landed under `bd-xxrfvu`, batch verdict pending. | Not touched. |
| `parse_hosts_line` IPv4 byte validation | Already landed under `bd-43e21q`, batch verdict pending. | Not touched. |
| `parse_aliases_line` member split/filter/collect removal | This batch. | Pending focused criterion verdict. |

## Keep / Reject Rule For Batch Validation

Keep only if the later focused benchmark on the same comparable worker shows
`parse_aliases_line_typical` improves without any aliases parser conformance
regression. Reject and revert/route deeper if the row is neutral/slower or if
any parser behavior diverges from the inline guards.
