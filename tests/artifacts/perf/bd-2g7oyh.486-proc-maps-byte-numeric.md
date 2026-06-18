# bd-2g7oyh.486 proc maps byte numeric parser

Date: 2026-06-18
Agent: cod-a
Status: code-first batch-test pending

## Target

`/proc/<pid>/maps` parsing feeds host symbol resolution, `dlfcn` map scans,
and pthread stack-bound discovery. The existing parser split the line into
borrowed `&str` fields, then parsed the numeric fields by pre-scanning the
string and calling `from_str_radix` / `str::parse`.

This bead adds a focused parser-bench row:

```text
resolv_parsers_bench parse_maps_line_typical
```

## Negative-Evidence Screen

Skipped no-repeat or owned families from the active no-gaps campaign:

- `memchr_absent`, `memcmp_*`, `malloc_free_256`, and adjacent `log2f`/math
  retunes: prior proof-clean variants missed or regressed the same-worker gate.
- `netgroup` delimiter/single-pass retunes: prior proof-clean delimiter parser
  regressed; not retried.
- `mntent` has an active `cc` parity bead, so this pass avoids that file.
- Active peer leaves already cover stdio/printf, hosts, aliases, services,
  protocols, networks, group/passwd/shadow/gshadow, RPC, and proc route flags.

## Lever

Replace only the `/proc/<pid>/maps` numeric conversion helpers with checked
byte-level accumulators:

- hex `usize` address fields,
- hex `u64` offset fields,
- decimal `u64` inode fields.

Line splitting, path preservation, permission strings, public return type, ABI
callers, locale, errno, floating-point state, and RNG are unchanged.

## Isomorphism

- Empty numeric fields still reject.
- Signed numeric fields still reject.
- Non-hex address/offset bytes still reject.
- Non-decimal inode bytes still reject.
- Uppercase and lowercase hex remain accepted.
- High 64-bit address rows remain accepted on the supported target.
- Numeric overflow now rejects through explicit checked arithmetic.
- `parse_maps_range` still agrees with `parse_maps_line` on successful rows.
- Path strings with embedded spaces and ` (deleted)` suffixes remain verbatim.

## Guard

Added focused unit coverage for address, offset, inode, and range overflow
rejection. Existing tests already cover whitespace collapse, optional path,
embedded spaces, deleted suffixes, signed-field rejection, high-address rows,
and range/full-parse agreement.

The later benchmark guard is the new `parse_maps_line_typical` row in
`crates/frankenlibc-bench/benches/resolv_parsers_bench.rs`.

## Retry-Condition Predicate

Keep only if later same-worker or directly comparable batch validation shows
`parse_maps_line_typical` has stable p50/mean improvement and the proc-maps
parser guard/conformance suite stays green. Reject/revert if the row regresses,
the improvement is within the variance envelope, or any malformed/overflow/path
contract diverges.

## Validation This Turn

Per campaign instruction: no tests, rch, or benchmarks in this batch. Intended
local checks:

```bash
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-core
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-bench --bench resolv_parsers_bench
```

Result after implementation: both passed. Existing unrelated warnings remain in
`iconv` (`unused_mut` in `emit_g1`, unused `EUCJX_P2_MULTI`) plus the build
script notice that no SMT solver was found for the stdio proof.
