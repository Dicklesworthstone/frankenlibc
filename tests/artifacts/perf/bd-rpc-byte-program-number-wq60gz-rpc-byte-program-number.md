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

## 2026-06-19 BOLD-VERIFY verdict

Same-worker `vmi1153651` parser batch:

- Baseline source `00cf7152d1f659397dec42616a8e660a64a8c849` with the bench row
  backported: p50 `166.474 ns`, mean `168.749 ns`.
- Candidate source: p50 `164.140 ns`, mean `179.322 ns`.
- Ratio old/new: p50 `0.986x`, mean `1.063x`.

Verdict: **NEUTRAL/LOSS, rejected**. The tiny p50 movement was not worth keeping
because mean and tail regressed. Reverted only the byte-number parser source
shape back to `from_utf8(...).parse::<i32>()`; kept signed/overflow guards and
the bench row. This is internal core-parser evidence, not a host-glibc ratio.
Focused `rpc::tests::parse_` guard passed 13 tests.
