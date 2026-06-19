# bd-4crkqx: `/etc/aliases` single-pass member scanner measured reject

## Bead

- `bd-4crkqx`
- Title: `perf: single-pass aliases member scanner`
- Assignee: `cod-a`
- Status after this batch: `closed`

## Routing Evidence

- Source profile: `tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`
- Bench row: `parse_aliases_line_typical`
- Baseline in artifact: p50 `116.8 ns/op`, mean `119.7 ns/op`
- Workload line: `postmaster: root, admin, oncall@example.com`

## Lever

Replace the `rest.split(',').filter_map(...).collect()` member parser with a
manual byte-range scanner and fuse comment/colon discovery into one scan before
trailing whitespace trim.

Expected benefit if the compiler does not already recover this shape:

- one fewer full-line scan on the common non-comment path;
- no generic split/filter/collect state machine on comma-separated members;
- no member-vector allocation for `x:` / whitespace-only member lists;
- first real member reserves the common small aliases capacity once.

## Same-Worker Verification

Command shape:

```text
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc \
FRANKENLIBC_RESOLV_BENCH_MODE=strict \
RCH_VERBOSE=1 \
rch exec -- cargo bench -p frankenlibc-bench --bench resolv_parsers_bench --profile release
```

`rch` selected the same worker for both runs:

- Worker: `hz2` (`root@178.104.77.29`)
- Baseline worktree: `/data/projects/.scratch/frankenlibc-cc-bd4crkqx-baseline-20260619T174620Z`
- Baseline commit: `f819823d8^` (`7cdf69121`)
- Candidate worktree: `/data/projects/.scratch/frankenlibc-cc-bd4crkqx-candidate-20260619T174620Z`
- Candidate commit: `f819823d8`
- Printed mode: `raw` for both runs. The env mode label was not forwarded by
  `rch`, so the comparison is still like-for-like but not a strict-mode label.

Focused row: `parse_aliases_line_typical`.

| Metric | Baseline split/filter/collect | Candidate manual scanner | Candidate / baseline |
| --- | ---: | ---: | ---: |
| p50 ns/op | 91.103 | 106.877 | 1.173x slower |
| mean ns/op | 91.762 | 116.684 | 1.272x slower |
| p95 ns/op | 95.303 | 171.807 | 1.803x slower |
| p99 ns/op | 96.391 | 192.406 | 1.996x slower |
| throughput ops/s | 10,897,706.887 | 8,570,123.415 | 0.786x |

Decision: reject and revert. The generic split/filter/collect path is faster
for this short aliases row than the manual comma scanner plus first-member
reserve branch.

## Behavior Guard

Existing inline aliases tests cover:

- blank and comment-only lines;
- missing colon and empty names;
- member whitespace trimming;
- empty member filtering;
- no-member rows;
- CRLF trimming;
- lookup and parse-all behavior.

Added guard:

- `parse_filters_whitespace_only_members` checks whitespace-only comma fields
  stay filtered after the manual scanner.

The original code-first batch did not run a benchmark, unit test, rch, or
conformance command per campaign instruction. The local gate was restricted to:

```text
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-core
```

First result in the shared checkout: blocked by unrelated peer-owned local dirt
in `crates/frankenlibc-core/src/stdio/printf.rs` where `#[derive(Debug, Clone)]`
was attached to `INLINE_SEGMENTS` instead of a struct/enum/union. The alias
parser itself was the only core source file touched by this bead.

Rerun after the peer printf/string changes landed cleanly: PASS. Existing
warnings remained in iconv (`unused_mut` in `emit_g1`, unused
`EUCJX_P2_MULTI`) and are unrelated to this aliases bead.

After the measured rejection, source was restored to the split/filter/collect
parser. The whitespace-only member guard remains valid for the restored parser.

Post-revert validation:

```text
rustfmt --check --edition 2024 crates/frankenlibc-core/src/aliases/mod.rs
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc cargo test -p frankenlibc-core aliases --lib -- --nocapture
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc cargo check -p frankenlibc-core
```

- `rustfmt` passed for the touched source file.
- `cargo test ... aliases --lib`: 30 passed, 0 failed, 3149 filtered.
- `cargo check -p frankenlibc-core`: passed with existing unrelated iconv
  warnings.

## Negative-Evidence Ledger

| Attempt family | Evidence | Batch decision |
| --- | --- | --- |
| `memchr_absent` panel/width/SWAR retunes | Prior same-worker ledgers marked these as no-ship or routing-only; memory notes forbid repeating this family without a new primitive. | Not retried. |
| `memcmp_*` generated/surface loop retunes | Prior focused gates rejected or routed away from surface loop families. | Not retried. |
| `malloc_free_256` hot-list/slab micro retunes | Prior focused gates rejected/blocked; not an alias parser workload. | Not retried. |
| `log2f` exponent/atanh extraction | Prior math gate rejected correctness/perf variants. | Not retried. |
| `netgroup` delimiter/single-pass parser | Previous parser-family single-pass delimiter attempt was proof-clean but slower. | Not retried. |
| `parse_services_line` / `parse_protocols_line` decimal byte parse | Already landed under `bd-9ran7n`, batch verdict pending. | Not touched. |
| `parse_networks_line` byte numeric parse | Already landed under `bd-xxrfvu`, batch verdict pending. | Not touched. |
| `parse_hosts_line` IPv4 byte validation | Already landed under `bd-43e21q`, batch verdict pending. | Not touched. |
| `parse_aliases_line` member split/filter/collect removal | Same-worker `hz2` focused row: baseline 91.103 ns p50 / 91.762 ns mean / 95.303 ns p95 / 96.391 ns p99; candidate 106.877 ns p50 / 116.684 ns mean / 171.807 ns p95 / 192.406 ns p99. | Rejected and reverted; do not retry manual comma scanner/reserve-shape variants without a new SIMD/memchr-backed multi-delimiter primitive or a longer-row workload where branch/setup costs amortize. |

## Retry Condition

Do not retry the same manual comma scanner family for `/etc/aliases` short rows.
Reopen only if a new primitive changes the scanner cost model, for example a
memchr/SWAR multi-delimiter scan shared across several `/etc` parsers, or if a
profile shows long aliases rows dominate and the current short-row benchmark no
longer represents production cost.
