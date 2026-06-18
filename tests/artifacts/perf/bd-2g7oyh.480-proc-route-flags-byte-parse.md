# bd-2g7oyh.480 proc route flag byte parser

Date: 2026-06-18
Agent: cod-a
Status: code-first batch-test pending

## Target

Profile handoff:
`tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`
records the resolver/NSS parser family around 100-140 ns per typical line.
This bead adds a focused row for the procfs path that feeds
`AI_ADDRCONFIG`:

```text
resolv_parsers_bench parse_proc_net_route_has_ipv4_typical
```

## Negative-Evidence Screen

Skipped no-repeat families from the current no-gaps campaign:

- `memchr_absent` panel-width, mask-fold, SWAR, and codegen retunes.
- `memcmp_*` surface loop and generated equality retunes.
- allocator hot-list/slab micro-retunes.
- `log2f` / `exp10` adjacent math route families.
- netgroup delimiter/parser retunes after the proof-clean slower attempt.
- current sibling resolver leaves already owned by cod-b:
  `bd-9ran7n`, `bd-xxrfvu`, `bd-43e21q`, and `bd-4crkqx`.

## Lever

`parse_proc_net_route_flags` parsed ASCII hex flags by first proving UTF-8 and
then calling `u32::from_str_radix`. `/proc/net/route` flags are byte-level
ASCII hex; the hot path does not need a `str` witness. The new helper parses
hex digits directly with checked `u32` arithmetic.

## Isomorphism

- Empty fields still reject.
- `+` / `-` signed fields still reject.
- Non-hex and non-UTF-8 bytes still reject.
- Uppercase and lowercase hex remain accepted.
- `u32::MAX` remains accepted and overflow remains rejected.
- Route scanning, loopback filtering, `RTF_UP` bit semantics, output shape,
  errno, locale, floating-point state, and RNG are unchanged.

## Guard

Added `proc_net_route_flags_byte_parser_matches_u32_hex_contract` covering
zero, ordinary route flags, mixed-case hex, `u32::MAX`, empty, signed,
non-hex, overflow, and non-UTF-8 rejection.

The later benchmark guard is the new
`parse_proc_net_route_has_ipv4_typical` row in `resolv_parsers_bench`.

## Retry-Condition Predicate

Keep only if later same-worker or directly comparable batch validation shows
`parse_proc_net_route_has_ipv4_typical` has stable p50/mean improvement and the
existing `AI_ADDRCONFIG` conformance guards stay green. Reject/revert if the
row regresses, the improvement is within the local variance envelope, or any
signed/malformed route-flag contract diverges.

## Validation This Turn

Per campaign instruction: no tests, rch, or benchmarks in this batch. Intended
local checks:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-core
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-bench --bench resolv_parsers_bench
```

Result after implementation: both passed. Existing unrelated warnings remain in
`iconv` (`unused_mut` in `emit_g1`, unused `EUCJX_P2_MULTI`) plus the build
script notice that no SMT solver was found for the stdio proof.
