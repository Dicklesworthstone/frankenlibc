# bd-43e21q: parse_hosts_line IPv4 byte validator

Status: code-first batch-test pending.

## Target

- Bead: `bd-43e21q`
- Crate: `frankenlibc-core`
- Function: `crates/frankenlibc-core/src/resolv/mod.rs::parse_hosts_line`
- Benchmark target: `resolv_parsers_bench::parse_hosts_line_typical`
- Baseline routing evidence:
  `tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`
  records `parse_hosts_line_typical` at p50/mean `114.4/116.5 ns`.

## Negative-Evidence Screen

Checked before edit:

- `bd-osbo8c`: netgroup throwaway `Vec<&[u8]>` already fixed.
- `bd-2g7oyh.9`: netgroup first-token early reject already shipped.
- `bd-2g7oyh.99`: netgroup single-pass delimiter parser was proof-clean but
  slower; do not retry netgroup delimiter micro-tuning.
- `bd-9ran7n`: services/protocols decimal byte parser already landed.
- `bd-xxrfvu`: networks number byte parser already landed.
- Memory ledger no-repeat families: `memchr_absent`, `memcmp`, allocator
  micro-levers, and `log2f` series lowering are excluded from this batch.

This bead deliberately targets the remaining resolver row with a different
primitive: IPv4 validation in `parse_hosts_line`, not string/memory kernels or
netgroup retuning.

## Lever

`parse_hosts_line` used to validate every address token by:

1. converting the bytes to UTF-8, then
2. trying `Ipv4Addr::from_str`, then
3. trying `Ipv6Addr::from_str`.

Typical `/etc/hosts` rows are plain IPv4 dotted decimals. The new private
`is_valid_ipv4_addr_bytes` validator accepts exactly four dotted decimal
components, rejects leading zero components to match Rust's IPv4 parser, bounds
each component to `<=255`, and falls back to the existing UTF-8 + IPv6 parser
only when the bytes are not plain IPv4.

This follows the graveyard/data-plane rule: keep hot deterministic parsers on
bytes, avoid unnecessary decoding, and prove constants with benchmark gates.

## Isomorphism

- Output address bytes: unchanged; the original `addr_field.to_vec()` is still
  returned.
- Hostname and alias order: unchanged; field splitting and allocation are
  untouched.
- IPv6 behavior: unchanged; non-IPv4 tokens still use the existing UTF-8
  `Ipv6Addr` parser.
- Invalid byte behavior: unchanged; non-UTF-8 non-IPv4 tokens reject.
- Floating point/RNG/locale/errno: N/A.

## Guard

Added unit coverage for:

- byte IPv4 validator accept cases: `0.0.0.0`, `127.0.0.1`,
  `192.168.1.1`, `255.255.255.255`;
- parity rejects matching `std::net::Ipv4Addr`: empty, wrong component count,
  empty component, extra component, signs, out-of-range component, suffix junk,
  and leading-zero components;
- `parse_hosts_line` rejects non-UTF-8 non-IPv4 address bytes.

Existing `parse_hosts_line` tests keep IPv6, comments, CRLF rows, missing
hostname rejection, and lookup behavior pinned.

## Validation

Campaign constraint for this batch: no tests/rch/bench. Local compiler guard:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-core
```

Result: pending at artifact creation time.
Result after implementation: passed. Existing unrelated `iconv` warnings
remain (`unused_mut` in `iconv/mod.rs` and dead `EUCJX_P2_MULTI` table), plus
the build-script notice that no SMT solver was found for the stdio proof.

## Batch Verdict Predicate

Later batch classification must run `resolv_parsers_bench` on the same worker
and same target-dir discipline used for the baseline.

- Keep only if `parse_hosts_line_typical` shows stable p50/mean improvement and
  the broader resolver parser table does not regress materially.
- Reject/revert if the row regresses, the improvement is within noise, or any
  hosts parser conformance guard fails.
- If rejected, do not retry nearby IPv4 parser variants unless a profile shows
  UTF-8/std parser validation remains top-5 after this exact helper is restored.
