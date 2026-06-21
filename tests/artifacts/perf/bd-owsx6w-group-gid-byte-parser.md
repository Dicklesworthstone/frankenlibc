# bd-owsx6w group GID byte parser

## Bead

- ID: `bd-owsx6w`
- Title: `perf: byte-parse /etc/group gid field`
- Assignee: `cod-b`
- Status after this verification batch: `closed`

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

## Measurement

Commands run:

```text
AGENT_NAME=BlackThrush RCH_WORKER=hz2 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo bench -p frankenlibc-bench --bench resolv_parsers_bench -- parse_group_line_typical --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
AGENT_NAME=BlackThrush RCH_WORKER=hz2 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench glibc_baseline_bench -- glibc_baseline_grp_lookup --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Results:

- Remote `hz2` parser row: `parse_group_line_typical` p50 `63.508 ns`, p95
  `156.264 ns`, p99 `157.824 ns`, mean `90.590 ns`.
- Remote `hz2` ABI `getgrnam_root`: FrankenLibC p50 `5558.772 ns`, host
  glibc p50 `11123.830 ns`, ratio `0.500x`, `WIN`.
- Remote `hz2` ABI `getgrgid_0`: FrankenLibC p50 `7766.673 ns`, host glibc
  p50 `7622.855 ns`, ratio `1.019x`, `NEUTRAL`.
- Initial `vmi1264463` parser attempt timed out during sync and fell back local:
  `parse_group_line_typical` p50 `60.012 ns`, mean `64.093 ns`. This is
  routing evidence only, not keep/reject proof.

## Validation

Commands run:

```text
AGENT_NAME=BlackThrush RCH_WORKER=hz2 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo test -p frankenlibc-core grp:: --lib
AGENT_NAME=BlackThrush RCH_WORKER=hz2 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo test -p frankenlibc-abi --test grp_abi_test getgr -- --nocapture
AGENT_NAME=BlackThrush RCH_WORKER=hz2 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo test -p frankenlibc-abi --test conformance_diff_getgrent --test conformance_diff_getbyid_r -- --nocapture
```

Result:

- PASS remote `hz2`: `cargo test -p frankenlibc-core grp:: --lib` passed 37
  tests, including `reject_gid_overflow_sign_and_trailing_junk` and
  `rejects_leading_plus_in_gid`.
- PASS remote `hz2`: `cargo test -p frankenlibc-abi --test grp_abi_test getgr`
  passed 36 filtered tests, including
  `getgrnam_getgrgid_ignore_signed_gid_rows`.
- PASS local fallback: `conformance_diff_getgrent` passed 1 test and
  `conformance_diff_getbyid_r` passed 3 tests, but `rch` reported no
  admissible workers (`insufficient_slots=8`, `active_project_exclusion=3`) and
  ran this command locally.
- Existing unrelated warnings remained in `iconv`, `math_abi`, `poll_abi`,
  `signal_abi`, `unistd_abi`, and `erf_tables`.
- Existing build notice remained: no SMT solver found for the generated stdio
  proof artifact, so solver execution was skipped.

## Verdict

Partial keep. The byte parser is retained because the deployed ABI group stack
beats host glibc on `getgrnam("root")` with conformance green. `getgrgid(0)` is
still neutral at p50, so this bead does not close the residual gid lookup gap.
Do not retry another GID field parser as that residual fix; route deeper to a
lower-cost lookup/index invalidation primitive if the gid row remains a target.

## 2026-06-19 Conformance Correction

The `/etc/group` gauntlet for `bd-2g7oyh.481` found that accepting a leading
`+` made `getgrnam_getgrgid_ignore_signed_gid_rows` fail in
`crates/frankenlibc-abi/tests/grp_abi_test.rs`. The byte parser remains, but
signed gid fields (`+N` and `-N`) are rejected again so NSS group lookups skip
those rows.
