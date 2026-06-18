# bd-2g7oyh.484 shadow line byte scan

## Lever

Replace `/etc/shadow` line parsing's temporary colon-field `Vec<&[u8]>`
and UTF-8 decimal conversion with a borrowed sequential field scanner plus
checked byte-level decimal accumulation.

## Why this lane

- `br ready` top allocator/stdio levers require a test-capable turn; this
  campaign turn is restricted to `cargo check`.
- Existing in-progress NSS parser leaves already cover proc route flags,
  passwd, group, and gshadow.
- Alien-graveyard parser guidance points at zero-allocation data-plane
  parsers and avoiding string-conversion hot paths.

## Negative-evidence ledger

- Do not retry saturated `memchr_absent`, `malloc_free_256`, `memcmp`, or
  `log2f` micro-levers from prior passes unless a fresh same-worker profile
  names a new primitive.
- This bead only attacks `/etc/shadow` parser allocation and UTF-8 parse
  overhead. If `parse_shadow_line_typical` fails to improve under the focused
  bench, revert or close as rejected and route to a different primitive.

## Contract guard

- Preserve glibc-style unsigned decimal parsing prefix rules: empty signed
  fields are `-1`, leading whitespace and `+` are accepted, `-`, trailing
  junk, and overflow reject the entry.
- Preserve optional/missing flag behavior: missing or empty flag decodes to
  `u64::MAX`.
- Preserve current extra-field behavior: fields after the flag are ignored.

## Pending benchmark

`crates/frankenlibc-bench/benches/resolv_parsers_bench.rs` now emits
`parse_shadow_line_typical` for the later same-worker batch gate.
