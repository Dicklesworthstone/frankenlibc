# bd-v4t889: resolv.conf option numeric byte parser

Status: code-first batch-test pending.

## Routing

- Parent: `bd-2g7oyh`
- Title: `perf: byte-parse resolv.conf option numerics`
- Source profile lane: `tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`
- Bench row added: `parse_resolv_conf_options_typical`

The resolver parser lane already tracks realistic `/etc` parser costs, and adjacent
NSS parser leaves moved decimal fields away from UTF-8 decode plus `str::parse`.
`ResolverConfig::parse` still parsed `options ndots:/timeout:/attempts:` through
that string path.

## Change

`parse_u32` in `crates/frankenlibc-core/src/resolv/config.rs` now performs checked
byte-level decimal accumulation:

- accepts the old `str::parse::<u32>` leading `+` form;
- rejects empty values, bare `+`, `-`, non-digits, and trailing junk;
- rejects `u32` overflow before clamp handling;
- preserves the existing clamps: `ndots <= 15`, `timeout in 1..=30`,
  `attempts in 1..=5`.

`crates/frankenlibc-bench/benches/resolv_parsers_bench.rs` now emits
`parse_resolv_conf_options_typical` for later same-worker classification.

## Guard

Added `test_options_numeric_byte_parser_edges` covering:

- `+N` acceptance for all three numeric options;
- junk, negative, and bare-plus rejection back to defaults;
- overflow rejection back to defaults.

## Negative-Evidence Screen

| Prior family | Ledger state | Action here |
| --- | --- | --- |
| `memchr_absent` panel/width/SWAR/folded probes | Repeated focused same-worker rejects or no-code closeouts. | Not retried. |
| `memcmp_*` load-shape retunes | Prior focused gates rejected shallow load-port changes. | Not retried. |
| `malloc_free_256` hot-list/slab/calloc-zero | Prior allocator micro-levers are rejected or test-capable gated. | Not touched. |
| `log2f` exponent/atanh/table variants | Prior math gates rejected nearby families. | Not retried. |
| `netgroup` delimiter/single-pass parser | Proof-clean parser attempt was slower. | Not retried. |
| active NSS parser leaves | Already owned by cod-a/cod-b with pending batch verdicts. | Not duplicated. |
| cc-owned stdio/allocator leaves | Higher nominal value but require full tests or are cc-owned. | Not claimed. |

## Isomorphism Proof

- Ordering preserved: yes. Option tokens are visited in the same order.
- Tie-breaking unchanged: yes. Later valid options still overwrite earlier values.
- Numeric semantics: unchanged for valid decimal and leading `+`; invalid and
  overflow values still fail instead of clamping.
- Floating point: N/A.
- RNG seeds: N/A.

## Pending Keep/Reject Predicate

Keep only if later same-worker batch timing shows `parse_resolv_conf_options_typical`
improves without resolver config conformance regressions. Reject and revert or route
deeper if the row is neutral/slower, if overflow/sign semantics diverge, or if clamp
behavior changes.

## Validation

Commands run this turn:

```bash
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-core
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-bench --bench resolv_parsers_bench
```

Result: both passed. Existing unrelated iconv warnings and the missing-SMT-solver
notice remained.

## 2026-06-19 BOLD-VERIFY verdict

Same-worker `vmi1153651` parser batch:

- Baseline source `00cf7152d1f659397dec42616a8e660a64a8c849` with the bench row
  backported: p50 `262.342 ns`, mean `270.402 ns`.
- Candidate source with this numeric parser plus `bd-2g7oyh.488` field scanner:
  p50 `310.177 ns`, mean `317.729 ns`.
- Ratio old/new: p50 `1.182x`, mean `1.175x`.

Verdict: **LOSS, rejected**. Reverted the numeric byte-parser source shape back
to UTF-8 plus `str::parse::<u32>()`; kept the option edge tests and bench row.
This is internal core-parser evidence, not a host-glibc ratio. Focused resolver
config guards passed.
