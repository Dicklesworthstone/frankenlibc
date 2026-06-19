# bd-2g7oyh.489 - resolver ndots early-exit dot scan

## Scope

- Bead: `bd-2g7oyh.489`
- Parent: `bd-2g7oyh`
- Lever: replace the full-name dot count in `ResolverConfig::should_try_absolute_first`
  with a byte scan that exits as soon as the configured `ndots` threshold is met.
- Bench target: `resolver_should_try_absolute_first_typical` in
  `crates/frankenlibc-bench/benches/resolv_parsers_bench.rs`.

## Routing Evidence

The resolver parser lane is a realistic NSS/resolv hot path and avoids previously
rejected string/search micro-lever families. The selected function is called for
ordinary DNS query routing; typical multi-label names only need to prove that the
threshold has been reached, not count every remaining label separator.

## Behavior Guard

- `ndots:0` remains absolute-first for all names, including empty strings.
- ASCII dot counting semantics are unchanged for ordinary host/query names.
- Names below the threshold still return `false`.
- Names with enough dots return `true` after the threshold dot is observed.

## Negative-Evidence Ledger

| Attempt | Status | Evidence |
| --- | --- | --- |
| Full `name.bytes().filter(...).count()` in `should_try_absolute_first` | Replaced | Correct but always scans the entire query name, even after `ndots` is already satisfied. |
| Early-exit byte scan for `ndots` threshold | Kept for batch testing | Code-first guard added; crate checks pending in this batch. |
| Retrying `memchr_absent`, generic `memcmp`, allocator micro-levers, or `log2f` cuts | Avoided | Prior same-campaign ledger marks those families as rejected or noisy; this bead routes into resolver control-path work instead. |

## Validation

- `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-core`: passed
- `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-bench --bench resolv_parsers_bench`: passed
- Full tests, `rch`, and Criterion: intentionally not run in this code-first batch per campaign instruction.
