# bd-2g7oyh.485 snprintb stream names

## Rejected lever

Tested replacing `snprintb` and `snprintb_m` bit-name collection with a
streaming format-string visitor. The old path parsed the full format into a
temporary `Vec<&[u8]>` and then rendered it. The candidate emitted each matching
name while walking the format bytes, eliminating that allocation and second
pass.

## Why this lane

- `br ready` top allocator/stdio leaves are assigned to `cc` and carry
  test-capable correctness notes; this turn is restricted to crate-scoped
  `cargo check`.
- The current NSS parser streak already covered proc route flags, passwd,
  group, gshadow, and shadow leaves, so this avoids duplicating peer work.
- Alien-graveyard parser guidance points at zero-allocation scanner/transducer
  hot paths. `snprintb` is a BSD/libutil diagnostic formatter over packed
  flags, so the realistic workload is interface/kernel-style bit-name rendering.

## Benchmark guard

`crates/frankenlibc-bench/benches/stdio_bench.rs` has
`stdio_snprintb/named_bits_stream_12`, a fixed 12-name flag corpus with mixed
sparse, dense, and all-bits values. That row is the reusable Criterion gate for
future `snprintb` formatter work.

## Measured verdict

No host-glibc comparator exists for BSD `snprintb`, so this row is explicitly
old-vs-new only. Same-worker `vmi1149989` Criterion evidence rejected the
streaming visitor:

| Workload | Old collect-Vec p50 | Streaming visitor p50 | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `stdio_snprintb/named_bits_stream_12` | 1.3316 us | 1.3500 us | 1.014x | NEUTRAL/REJECT | Reverted source to `collect_set_names`; kept the bench hook and behavior guard. |

Commands:

- Baseline worktree at `8143748abe186ee6f568b60f456f73da49f41a57` with the
  benchmark hook patched in:
  `AGENT_NAME=BlackThrush RCH_WORKER=hz1 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo bench -p frankenlibc-bench --bench stdio_bench -- stdio_snprintb/named_bits_stream_12`
- Candidate/current tree before revert:
  `AGENT_NAME=BlackThrush RCH_WORKER=vmi1149989 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo bench -p frankenlibc-bench --bench stdio_bench -- stdio_snprintb/named_bits_stream_12`

The candidate median was 1.4% slower than the old path and had high outliers.
Under the campaign rule to revert regressions and near-zero gains, the source
lever is rejected. Do not retry this exact streaming visitor without a fresh
allocation-dominant or multiline-specific profile.

## Contract guard

`crates/frankenlibc-core/src/stdio/snprintb.rs` keeps
`streaming_name_scan_preserves_nul_stop_and_strays`, covering:

- Stray printable bytes before the first bit spec are ignored.
- NUL terminates the format body, so later bit specs are not rendered.
- Single-line and multiline output keep the same bit-name order and wrapping
  behavior.

## Negative-evidence ledger

- Do not retry saturated `memchr_absent`, `memcmp`, `malloc_free_256`, or
  `log2f` micro-levers from prior passes unless a fresh same-worker profile
  names a different primitive or input shape.
- Do not repeat the landed NSS parser split/byte-scan leaves for group,
  passwd, gshadow, or shadow. Route any follow-up there through a focused
  same-worker Criterion miss, not the generic "remove Vec" family.
- Do not claim allocator `calloc` mmap-zero or stdio `fwrite`/`fread` direct
  bypass in a check-only turn; those leaves need broader behavior proof.
- This batch rejects `snprintb` temporary-name-vector removal. Route follow-up
  through a different formatter primitive or a workload where multiline
  wrapping or allocation dominates the profile.

## Local validation

- `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo test -p frankenlibc-core stdio::snprintb --lib`
  passed on `hz1`: 13 passed, 0 failed.
- `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo check -p frankenlibc-bench --bench stdio_bench`
  passed on `hz1`.
- Both commands reported the known pre-existing `iconv` unused/dead-code
  warnings plus the existing unused math constant; no new warning is from
  `snprintb`.
- `cargo fmt --check -p frankenlibc-core` remains blocked by broad pre-existing
  formatting drift in unrelated core modules and generated iconv tables.
- `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo clippy -p frankenlibc-core --lib -- -D warnings`
  failed on `vmi1293453` with pre-existing unrelated core lints in
  `iconv`, `math`, `resolv`, and `stdio::printf`; no failure cited
  `stdio::snprintb`.

## Landing note

The source/bench/artifact payload landed in shared commit
`545d57ee9c3ee1b110cf86444737fe920e13d42f` after a concurrent commit picked up
the staged index. This follow-up ledger records the measured reject and source
revert without rewriting the peer-owned commit.
