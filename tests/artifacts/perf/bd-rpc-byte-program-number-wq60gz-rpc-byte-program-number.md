# bd-rpc-byte-program-number-wq60gz rpc program-number byte parse

## Lever

Replace `/etc/rpc` parser program-number conversion from
`from_utf8(...).parse::<i32>()` with a checked byte-level signed decimal parser.

## Why this lane

- `br ready` still surfaces allocator/stdio items that need a test-capable
  turn; this campaign pass is limited to `cargo check`.
- Peer-owned active leaves cover stdio, resolver/NSS hosts/services/networks,
  aliases, proc route flags, passwd, group, shadow, and gshadow.
- `/etc/rpc` is an adjacent realistic libc database parser with a remaining
  string-conversion hot path and a narrow behavior-preserving proof surface.

## Negative-evidence ledger

- Do not retry saturated `memchr_absent`, `malloc_free_256`, `memcmp`, or
  `log2f` micro-levers without a new same-worker profile naming a different
  primitive.
- Do not collide with peer-owned stdio/snprintb or resolver/NSS parser leaves.
- This bead only attacks `/etc/rpc` program-number conversion. If the later
  `parse_rpc_line_typical` row does not improve under the focused batch gate,
  close it rejected and route to a different data-plane primitive.

## Contract guard

- Preserve `int r_number` signed range: accept `i32::MIN..=i32::MAX`.
- Preserve decimal sign handling: `+N` and `-N` follow Rust/glibc-style integer
  parsing, while bare signs reject.
- Preserve rejection for non-decimal tokens, non-ASCII bytes, and overflow.
- Preserve comment stripping, blank/comment skipping, alias order, and
  case-insensitive lookup behavior.

## Pending benchmark

`crates/frankenlibc-bench/benches/resolv_parsers_bench.rs` now emits
`parse_rpc_line_typical` for the later same-worker batch gate.
