# bd-2g7oyh.485 snprintb stream names

## Lever

Replace `snprintb` and `snprintb_m` bit-name collection with a streaming
format-string visitor. The old path parsed the full format into a temporary
`Vec<&[u8]>` and then rendered it. The new path emits each matching name while
walking the format bytes, eliminating that allocation and second pass.

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

`crates/frankenlibc-bench/benches/stdio_bench.rs` now has
`stdio_snprintb/named_bits_stream_12`, a fixed 12-name flag corpus with mixed
sparse, dense, and all-bits values. That row is the later Criterion batch gate
for this lever.

## Contract guard

`crates/frankenlibc-core/src/stdio/snprintb.rs` now has
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
- This batch only claims `snprintb` temporary-name-vector removal. If
  `stdio_snprintb/named_bits_stream_12` fails to improve in the later batch
  gate, reject/revert this lever and route to a different formatter primitive.

## Local validation

- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b AGENT_NAME=BlackThrush cargo check -p frankenlibc-core`
  passed.
- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b AGENT_NAME=BlackThrush cargo check -p frankenlibc-bench --benches`
  passed.
- Per campaign instruction, no tests, `rch`, or Criterion benchmark run was
  executed in this code-first turn.
