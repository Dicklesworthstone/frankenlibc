# bd-2g7oyh.487 getopt fused optstring lookup

## Lever

`getopt::state::step_short` classified every short option by scanning the
optstring once for GNU `W;` routing and again for argument mode. This batch
adds a single byte-level `getopt_spec_match` lookup that returns both facts and
keeps the public helper APIs as wrappers.

## Guard

- Duplicate optstring entries still use the first occurrence.
- `W;` still routes separated and inline long-option specs.
- `:` and `;` remain optstring metadata, not selectable options.
- Optional and required argument modes keep their existing suffix semantics.

## Benchmark Target

`baseline_capture_bench` now includes `getopt_short_bundle_typical`, a realistic
CLI startup scan over bundled short options, attached required args, GNU `W;`
routing, and a terminal operand.

## Negative Evidence Ledger

- Did not retry memchr_absent panel/width/SWAR families; prior focused gates
  were proof-clean but slower or routing-only.
- Did not retry memcmp load-shape or malloc hot-list/slab families; prior
  same-worker gates rejected them or routed them to deeper primitives.
- Did not retry log2f exponent/atanh families or netgroup delimiter scans.
- Avoided ready calloc/fwrite beads because their own notes require
  test-capable validation, which this campaign turn forbids.
- Avoided already-owned NSS parser leaves: hosts, services, protocols,
  networks, aliases, group, passwd, shadow, gshadow, rpc, proc route, proc maps.

## Pending Verdict

Code-first validation is limited to crate-scoped `cargo check`. Keep/reject
must be decided later by same-worker Criterion timing against the pre-change
parent and any host/original comparison available for CLI parser workloads.
