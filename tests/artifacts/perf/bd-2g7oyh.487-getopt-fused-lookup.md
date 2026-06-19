# bd-2g7oyh.487 getopt fused optstring lookup

## Lever

`getopt::state::step_short` classified every short option by scanning the
optstring once for GNU `W;` routing and again for argument mode. This batch
adds a single byte-level `getopt_spec_match` lookup that returns both facts and
keeps the public helper APIs as wrappers.

## Guard

- Duplicate optstring entries still use the first occurrence.
- `W;` still routes separated and inline long-option specs.
- `:` and `;` remain optstring metadata, not selectable options.
- Optional and required argument modes keep their existing suffix semantics.

## Benchmark Target

`baseline_capture_bench` now includes:

- `getopt_short_bundle_typical`: FrankenLibC-only CLI startup scan over bundled
  short options, attached required args, GNU `W;` routing, and a terminal
  operand.
- `getopt_short_bundle_glibc_comparable`: same short-option stream, measured
  head-to-head against host glibc `getopt`.

The host glibc path is loaded with `dlmopen(LM_ID_NEWLM, "libc.so.6", ...)` and
the harness resets both the isolated libc `opt*` symbols and the process-visible
`opt*` symbols. This is required because the bench binary links
`frankenlibc_abi`, which exports `optind`/`optarg`/`opterr`/`optopt` and can
otherwise interpose glibc's state variables. A preflight asserts both the option
stream checksum and final `optind` before Criterion timing starts.

## Negative Evidence Ledger

- Did not retry memchr_absent panel/width/SWAR families; prior focused gates
  were proof-clean but slower or routing-only.
- Did not retry memcmp load-shape or malloc hot-list/slab families; prior
  same-worker gates rejected them or routed them to deeper primitives.
- Did not retry log2f exponent/atanh families or netgroup delimiter scans.
- Avoided ready calloc/fwrite beads because their own notes require
  test-capable validation, which this campaign turn forbids.
- Avoided already-owned NSS parser leaves: hosts, services, protocols,
  networks, aliases, group, passwd, shadow, gshadow, rpc, proc route, proc maps.

## Measured Verdict

Command:

```bash
AGENT_NAME=cod-a \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench baseline_capture_bench getopt_short_bundle_glibc_comparable -- --noplot
```

Worker: `ovh-a`; default bench profile (thin-LTO).

| Mode | p50 ns/op | mean ns/op | p95 ns/op |
|---|---:|---:|---:|
| FrankenLibC core, fused lookup | 93.699 | 96.687 | 166.625 |
| Host glibc `getopt` | 168.676 | 188.519 | 194.829 |

Ratio vs glibc: `0.556x` p50 (`93.699 / 168.676`), lower is better.

Verdict: **WIN**. Keep the fused lookup.

## Harness Negative Evidence

The first host-glibc attempts are not recorded as perf evidence:

- `dlopen("libc.so.6")` + `dlsym("optind")` observed libc's own `optind`, while
  glibc `getopt` advanced the process-visible interposed `optind`; final
  `optind` parity failed.
- `RTLD_DEEPBIND` was rejected by the remote worker when loading `libc.so.6`.
- A post-revert context run with the corrected host reset also beat glibc
  (`61.777 ns` vs `105.433 ns`, ratio `0.586x` on `hz2`), but that was the
  two-scan baseline, not this fused candidate.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/getopt/parse.rs crates/frankenlibc-core/src/getopt/state.rs crates/frankenlibc-bench/benches/baseline_capture_bench.rs`: passed.
- `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a rch exec -- cargo test -p frankenlibc-core getopt --lib`: 39 passed.
- `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a rch exec -- cargo check -p frankenlibc-bench --features abi-bench --bench baseline_capture_bench`: passed before final harness correction; final Criterion run rebuilt and executed the bench target successfully.
- `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a rch exec -- cargo clippy -p frankenlibc-core --lib -- -D warnings`: blocked because `cargo-clippy` is not installed for `nightly-2026-04-28-x86_64-unknown-linux-gnu` on the selected worker.
