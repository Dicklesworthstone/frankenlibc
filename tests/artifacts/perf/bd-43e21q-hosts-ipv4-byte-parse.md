# bd-43e21q: parse_hosts_line IPv4 byte validator

Status: certified keep on 2026-07-14.

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

## Focused Certification Verdict (2026-07-14)

The retained pre-lever parser and current production parser matched exactly on
2,246 complete-result cases. The corpus exhausts each legal IPv4 octet value in
each component, adds every leading-zero spelling and a dense 256..300 overflow
band, and covers malformed IPv4, IPv6, comments/CRLF, missing hostnames, and
non-UTF-8 input.

The sole foreground benchmark was:

```bash
RCH_WORKER=vmi1153651 RCH_WORKERS=vmi1153651 RCH_QUEUE_WHEN_BUSY=1 \
RCH_REQUIRE_REMOTE=1 RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR \
CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_cod_strverscmp_raw \
rch exec -- cargo bench -j 1 --profile release -p frankenlibc-bench \
  --bench resolv_parsers_bench -- hosts-ipv4-ab
```

Actual worker `vmi1153651`, 60 order-rotated samples, 10,000 full parser calls
per arm and sample:

| arm | p50 ns | mean ns |
|---|---:|---:|
| exact incumbent parser | 222.603 | 287.778 |
| byte-validator candidate | 184.970 | 227.328 |
| candidate null A | 183.355 | 230.605 |
| candidate null B | 179.620 | 245.275 |

Candidate/incumbent was `0.8309x` at p50 (16.9% less time, 1.20x faster) and
`0.7899x` by mean (21.0% less time). The null p50 ratio was `0.9796x`, placing
the target win well beyond paired noise. RCH rotated the requested warm identity
to a fresh pool target, so the ordinary `release` build took 5m35s; no
`release-perf`, second benchmark, or local Cargo ran.

## Batch Verdict Predicate

Later batch classification must run `resolv_parsers_bench` on the same worker
and same target-dir discipline used for the baseline.

- Keep only if `parse_hosts_line_typical` shows stable p50/mean improvement and
  the broader resolver parser table does not regress materially.
- Reject/revert if the row regresses, the improvement is within noise, or any
  hosts parser conformance guard fails.
- If rejected, do not retry nearby IPv4 parser variants unless a profile shows
  UTF-8/std parser validation remains top-5 after this exact helper is restored.

Verdict: **KEEP**. The focused current-binary target cleared both p50 and mean,
the complete-result certificate passed, and no other resolver parser source is
part of the lever. The broader table was intentionally not rerun under the
one-foreground-benchmark constraint.
