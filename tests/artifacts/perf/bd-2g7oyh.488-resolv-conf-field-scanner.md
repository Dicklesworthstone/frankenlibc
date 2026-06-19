# bd-2g7oyh.488 - resolv.conf byte-field scanner

## Scope

- Bead: `bd-2g7oyh.488`
- Lever: replace `ResolverConfig::parse_line`'s split/filter field iterator with an indexed byte-field scanner over the same space/tab separators.
- Target workload: realistic resolver startup and reload parsing of `/etc/resolv.conf`.
- Benchmark target for batch timing: `parse_resolv_conf_options_typical` in `resolv_parsers_bench`.

## Routing Evidence

- `bv --robot-triage` ranked `bd-2g7oyh` as the top in-progress perf epic.
- Ready allocator and stdio leaves (`bd-7ak6cm`, `bd-hqo6b6`, `bd-wutxl6`) need test-capable correctness gates and are not appropriate for this cargo-check-only turn.
- The resolver parser lane already has focused Criterion coverage and prior realistic `/etc` parser rows.

## Negative-Evidence Ledger

Do not retry these families unless the retry predicate below is satisfied:

- `memchr_absent` panel-width/SWAR/folded-probe variants: repeatedly failed or regressed under focused timing.
- `memcmp` load-shape changes: rejected in prior no-gaps passes.
- `malloc` hot-list/slab/calloc-zero changes: correctness-sensitive or prior allocator micro-levers regressed; retry only with allocator differential + recycled-block stress coverage.
- `log2f` exponent/atanh reshapes: rejected by focused gates.
- Netgroup delimiter and already-owned NSS parser leaves: avoid duplicate work with active swarm lanes.

Retry predicate for this lever:

- Keep only if a later same-worker Criterion batch shows `parse_resolv_conf_options_typical` or a full resolv.conf parser row improves beyond noise without any resolver conformance regression.
- Reject and revert if parser rows regress materially, if conformance finds changed resolver(5) behavior, or if the improvement is within noise.

## Behavior Preservation

- Field separators remain exactly ASCII space and tab, matching the previous `split(|b| b == b' ' || b == b'\t')` grammar after outer ASCII trim.
- Empty fields from repeated separators are skipped in the same order.
- `nameserver`, `domain`, `search`, and `options` directive ordering is unchanged.
- Search list capping still counts the first `MAX_SEARCH_DOMAINS` fields.
- Numeric option clamp behavior is delegated to the existing byte parser.

## Validation

Passed for this turn:

- `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-core`

Notes:

- Existing iconv warnings remain.
- Existing missing-SMT-solver notice remains.

Not run by campaign instruction:

- Criterion benchmarks
- `rch`
- tests/conformance
