# bd-2g7oyh.481: /etc/group single-pass colon-tail parser

## Bead

- `bd-2g7oyh.481`
- Title: `perf: single-pass /etc/group colon-tail parser`
- Assignee: `cod-b`
- Status after this batch: `measured partial keep`

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
fields, empty names, optional member list, CRLF trimming, large `gid`, signed
`gid` rejection, duplicate lookup order, and empty comma-token filtering.

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
| `parse_group_line` colon-field Vec plus tail join removal | This batch. | Measured partial keep: deployed `getgrnam("root")` wins vs glibc; deployed `getgrgid(0)` is neutral and routed deeper. |

## Measured Head-To-Head Evidence

Command:

```text
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b/criterion-bd-2g7oyh-481-final-20260619T0414 \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- glibc_baseline_grp_lookup \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Worker: `hz2`; release bench profile; rch rewrote the target dir to
`/data/projects/frankenlibc/.rch-target-hz2-pool-2740363b0b76e0a08f9b35b4f209a994`.

| Workload | FrankenLibC p50 | glibc p50 | Ratio vs glibc | Verdict | Action |
|---|---:|---:|---:|---|---|
| `getgrnam("root")` through `/etc/group` | 9.788 us | 24.779 us | 0.395x | WIN | Keep the splitn parser as a partial deployed win. |
| `getgrgid(0)` through `/etc/group` | 24.631 us | 24.435 us | 1.008x | NEUTRAL | Do not count as a win; route the gid lookup path deeper. |

Criterion means:

- `getgrnam("root")`: FrankenLibC `9.989 us`, glibc `25.431 us`, ratio
  `0.393x`.
- `getgrgid(0)`: FrankenLibC `25.114 us`, glibc `24.827 us`, ratio `1.012x`.

The benchmark preflight asserted non-null results, gid parity, and group-name
parity before timing.

## Validation

- PASS: `cargo check -p frankenlibc-bench --features abi-bench --bench glibc_baseline_bench`.
- PASS: `cargo test -p frankenlibc-core grp::tests:: -- --nocapture`: 37 passed.
- PASS: `cargo test -p frankenlibc-abi --test grp_abi_test getgr -- --nocapture`: 35 passed, 5 ignored.
- PASS: `cargo test -p frankenlibc-abi --test conformance_diff_getbyid_r -- --nocapture`: 3 passed.
- PASS: `cargo test -p frankenlibc-abi --test conformance_diff_getgrent -- --nocapture`: 1 passed.
- Existing unrelated warnings remained in `iconv`, `math_abi`, `poll_abi`,
  `signal_abi`, `unistd_abi`, and `erf_tables`.

Conformance correction found by this gauntlet: the adjacent group gid byte parser
accepted `+27`, which made `getgrnam_getgrgid_ignore_signed_gid_rows` fail. The
byte parser was kept, but signed gid fields are rejected again so NSS group
lookups skip those rows.

Earlier same-turn `hz1` evidence before that conformance correction is retained
in the central ledger: `getgrnam("root")` was a win at `0.717x`, while
`getgrgid(0)` was a loss at `1.102x`. The corrected-source `hz2` rerun above is
the final keep/reject input for the shipped code.

## Keep / Reject Decision

Keep the splitn colon-tail parser as a **partial** deployed win because
`getgrnam("root")` beats host glibc by `0.395x` p50 and the conformance guard is
green. Record `getgrgid(0)` as real negative evidence (`1.008x` neutral) and do not
retry colon-tail parsing for that gap; route the gid lookup/cache path deeper.
