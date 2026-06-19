# bd-li0so3: `/etc/hosts` hostname field scanner measured reject

Date: 2026-06-19
Agent: BlackThrush / cod-a
Status: measured reject; source reverted

## Bead

- `bd-li0so3`
- Title: `perf: single-pass /etc/hosts hostname field scanner`
- Assignee: `cod-a`
- Status after this batch: `closed`

## Routing Evidence

- Source profile: `tests/artifacts/perf/20260601-perf-26a69011/resolv_parsers_bench.summary.md`
- Bench row: `parse_hosts_line_typical`
- Baseline in artifact: p50 `114.4 ns/op`, mean `116.5 ns/op`
- Workload line: `127.0.0.1   localhost localhost.localdomain`

## Lever

Rejected lever: `parse_hosts_line` no longer drives the hot row through
`split(...).filter(...).collect()` before address validation. It now uses a
small byte-field scanner to capture the first field, validates the address
before allocating hostname vectors, and then pushes remaining fields in input
order with a small common-case reserve.

Expected benefit if the compiler did not already recover this shape:

- one less generic split/filter/collect state machine in the common parser row;
- invalid first fields reject before allocating hostname `Vec`s;
- common one- or two-hostname rows reserve once instead of growing from zero.

## Behavior Guard

Added `parse_hosts_field_scanner_preserves_comments_and_empty_fields`, covering:

- leading whitespace before the address;
- mixed space/tab runs between fields;
- inline comment termination;
- rows with no hostname before the comment;
- malformed first fields with otherwise valid-looking hostnames.

Existing hosts parser conformance/fuzz tables still pin IPv4, IPv6, comments,
blank rows, CRLF, lookup behavior, and output-substring invariants.

## Negative-Evidence Ledger

| Attempt family | Evidence | Batch decision |
| --- | --- | --- |
| `memchr_absent` panel/width/SWAR retunes | Prior same-worker ledgers marked panel-width and folded-probe families as no-ship. | Not retried. |
| `memcmp_*` load-port/surface retunes | Prior focused gates rejected shallow loop retunes. | Not retried. |
| `malloc_free_256` hot-list/slab micro retunes | Prior focused gates rejected or blocked nearby allocator micro-levers. | Not retried. |
| `log2f` exponent/atanh extraction | Prior math gate rejected the nearby series/exponent family. | Not retried. |
| `netgroup` delimiter/single-pass parser | Prior parser-family delimiter attempt was proof-clean but slower. | Not retried. |
| `parse_services_line` / `parse_protocols_line` decimal byte parse | Already landed under `bd-9ran7n`, batch verdict pending. | Not touched. |
| `parse_networks_line` byte numeric parse | Already landed under `bd-xxrfvu`, batch verdict pending. | Not touched. |
| `parse_hosts_line` IPv4 byte validation | Already landed under `bd-43e21q`, batch verdict pending. | Not duplicated. |
| `parse_hosts_line` hostname split/filter/collect removal | This batch. | Rejected/reverted after same-worker regression. |

## Same-Worker Benchmark Verdict

Command shape:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a-bd-li0so3-{baseline,candidate} \
CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-a/criterion-bd-li0so3-* \
RCH_REQUIRE_REMOTE=1 rch exec -- \
cargo bench -p frankenlibc-bench --bench resolv_parsers_bench -- \
parse_hosts_line_typical --noplot --sample-size 100 --warm-up-time 1 --measurement-time 3
```

Decisive comparable rows were both remote `vmi1149989`:

| Source | Worker | p50 | p95 | p99 | mean | Verdict |
|---|---|---:|---:|---:|---:|---|
| Baseline `3ac324347` split/filter/collect | `vmi1149989` | 74.106 ns | 80.096 ns | 88.041 ns | 69.717 ns | baseline |
| Candidate `a06a0a8f8` field scanner | `vmi1149989` | 92.461 ns | 104.067 ns | 111.742 ns | 94.178 ns | reject |

Ratios candidate/baseline:

- p50: `1.248x` slower.
- mean: `1.351x` slower.
- p95: `1.299x` slower.
- p99: `1.269x` slower.

Reject reason: the bespoke field scanner is slower than the standard
split/filter/collect path on the realistic hosts row. Do not retry this scanner
family unless a fresh profile shows allocation dominates a different hosts-file
shape. Route deeper to address validation or a generated parser that removes
both splitting and per-hostname allocation without adding scanner overhead.

## Revert Action

Restored the faster baseline shape:

```rust
let mut fields = line
    .split(|&b| is_resolver_field_separator(b))
    .filter(|f| !f.is_empty());
let addr_field = fields.next()?;
let hostnames: Vec<Vec<u8>> = fields.map(|f| f.to_vec()).collect();
```

Removed the `next_resolver_field` helper and its scanner-specific guard test.

## Validation

- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b AGENT_NAME=BlackThrush cargo check -p frankenlibc-core`
  passed in the original code-first turn.
- Post-revert validation passed:
  - `rustfmt --check --edition 2024 crates/frankenlibc-core/src/resolv/mod.rs`
  - `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a-local cargo test -p frankenlibc-core resolv::tests::parse_hosts --lib -- --nocapture`
    passed 10 hosts parser tests.
  - `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a-local cargo check -p frankenlibc-core`
  - `git diff --check -- crates/frankenlibc-core/src/resolv/mod.rs tests/artifacts/perf/bd-li0so3-hosts-field-scanner.md docs/RELEASE_READINESS_SCORECARD.md .beads/issues.jsonl`
- Existing unrelated warnings remained in iconv (`unused_mut` in `emit_g1`,
  unused `EUCJX_P2_MULTI`) plus the missing-SMT-solver notice.
