# bd-owsx6w group GID byte parser

## Bead

- ID: `bd-owsx6w`
- Title: `perf: byte-parse /etc/group gid field`
- Assignee: `cod-b`
- Status after this batch: `in_progress`

## Routing Evidence

- Source profile: `tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`
- Nearby parser rows from that profile sit in the `99-138 ns` p50 band and the
  ledger identifies parser allocation/conversion overhead as the recurring cost.
- `bd-2g7oyh.481` already removed `/etc/group` colon-tail allocation. The
  remaining `gid` path still scanned for digits, decoded UTF-8, then used
  `str::parse::<u32>` on every accepted group line.

## Lever

`parse_u32_decimal` now performs checked byte-level decimal accumulation:

- preserves leading ASCII whitespace skipping;
- rejects empty/sign-only, `+`, `-`, trailing junk, whitespace suffixes, and
  overflow;
- returns the same `u32` value for valid fields without UTF-8 decoding or the
  generic integer parser.

This is the data-plane parser/transducer primitive from the alien-graveyard
screen: keep the hot path as one byte pass with no format conversion layer.

## Bench / Guard

- Added `resolv_parsers_bench` row: `parse_group_line_typical`.
- Existing inline group parser tests continue to cover comment/blank rejection,
  optional member list, CRLF trimming, duplicate lookup order, empty member-token
  filtering, and extra-colon member-tail absorption.
- Added focused guard coverage for `u32` overflow, signed field rejection,
  trailing junk/space rejection, and leading whitespace before unsigned digits.

## Negative-Evidence Ledger

| Attempt family | Evidence | Batch decision |
| --- | --- | --- |
| `memchr_absent` panel/width/SWAR/resolver retunes | Prior same-worker ledgers and memory mark these as no-retry unless the primitive family changes. | Not retried. |
| `memcmp_*` load-shape/surface loop retunes | Prior focused gates rejected p50/mean or Criterion center despite proof-clean candidates. | Not retried. |
| `malloc_free_256` hot-list/slab micro retunes | Prior focused gates rejected or blocked; not a parser workload. | Not retried. |
| `log2f` exponent/atanh lowering | Correctness-clean but slower; next route requires generated minimax/table or disassembly-backed lowering. | Not retried. |
| `netgroup` delimiter/single-pass parser | Prior proof-clean delimiter rewrite was slower under the focused gate. | Not retried. |
| `proc_maps`, `mntent`, `stdio`, `calloc` | Active peer/test-capable lanes. | Avoided. |
| `/etc/group` colon-tail allocation | Already landed as `bd-2g7oyh.481`; this batch only attacks GID conversion. | Not duplicated. |

## Validation

Campaign instruction for this batch permits cargo-check only, no tests, no
`rch`, and no Criterion run.

Commands run:

```text
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-core
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-bench --bench resolv_parsers_bench
```

Result:

- PASS: `cargo check -p frankenlibc-core`
- PASS: `cargo check -p frankenlibc-bench --bench resolv_parsers_bench`
- Existing unrelated warnings remained in `iconv`: `emit_g1` unused `mut` and
  `EUCJX_P2_MULTI` dead code.
- Existing build notice remained: no SMT solver found for the generated stdio
  proof artifact, so solver execution was skipped.

## Keep / Reject Rule

Keep only if the later same-worker batch shows `parse_group_line_typical`
improves in stable p50/mean and group parser conformance remains green. Reject
or route deeper if the row is neutral/slower or if any parser contract diverges.

## 2026-06-19 Conformance Correction

The `/etc/group` gauntlet for `bd-2g7oyh.481` found that accepting a leading
`+` made `getgrnam_getgrgid_ignore_signed_gid_rows` fail in
`crates/frankenlibc-abi/tests/grp_abi_test.rs`. The byte parser remains, but
signed gid fields (`+N` and `-N`) are rejected again so NSS group lookups skip
those rows.
