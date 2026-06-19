# bd-7ak6cm — calloc `alloc_zeroed` fresh-mmap skip — MEASURED REJECT

**Lever:** route fl `calloc` through `std::alloc::alloc_zeroed` (via a new
`arena.allocate_zeroed` / `pipeline.allocate_zeroed`) instead of
`pipeline.allocate(total)` + an unconditional `std::ptr::write_bytes(ptr, 0, total)`,
on the theory that large blocks served fresh from `mmap(MAP_ANONYMOUS)` are already
kernel-zeroed and the memset is pure waste (this is how glibc `calloc` avoids the
zero pass).

**Verdict:** REJECT — NEUTRAL at every size, slight LOSS at 1 MiB. Source reverted.
The reusable head-to-head bench (`crates/frankenlibc-bench/benches/calloc_glibc_bench.rs`)
is kept.

## Root cause (why the lever cannot win as written)

Rust's `System` allocator only forwards `alloc_zeroed` to libc `calloc` (the path
that carries the mmap-zeroed skip) when the layout alignment is `<= MIN_ALIGN`
(16 on x86-64). The membrane arena (`crates/frankenlibc-membrane/src/arena.rs`)
forces `align = align.max(32)` so it can carry its 24-byte `AllocationFingerprint`
header in front of the user region. Because `32 > MIN_ALIGN(16)`, the System
allocator's `alloc_zeroed` **always takes the fallback branch** —
`alloc(layout)` + `write_bytes(0, size)` — i.e. exactly the work the lever was
trying to remove. `alloc_zeroed` therefore never reaches the libc `calloc`
fast path; the candidate does the same memset as the baseline (plus the
over-aligned `posix_memalign` path), which is why 1 MiB is marginally slower.

The measurement confirms this directly: if `alloc_zeroed` were skipping the
memset, the `fl` (new) arm would not touch the pages, so at 1 MiB / 4 MiB it
would be dramatically cheaper than the `fl_old` arm (which memsets all pages).
Instead `fl ≈ fl_old` at every size.

## Method

- Worker: rch `ovh-a`. Single process, single run → fl-new, fl-old and glibc
  measured back-to-back on the same host (no cross-run worker drift).
- `fl` arm: exported `calloc(1, n)` (the lever / new path).
- `fl_old` arm: exported `malloc(n)` + `std::ptr::write_bytes(p, 0, n)` — reproduces
  the pre-lever cost model (`pipeline.allocate` then a full zero pass) through the
  identical fl allocator/membrane, isolating the memset as the only variable.
- `glibc` arm: host `calloc`/`free` resolved via `dlmopen(LM_ID_NEWLM, "libc.so.6")`
  so fl's `no_mangle` symbols do not interpose the host allocator.
- Each arm pairs its own `calloc`/`malloc`+`free`; pointers never cross allocators.

```
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench calloc_glibc_bench -- --measurement-time 2 --warm-up-time 1 --noplot
```

## Results (p50 ns/op, alloc+free cycle)

| size (B) | fl (new) | fl_old | new/old | glibc | fl_old mean | fl mean |
|---------:|---------:|-------:|--------:|------:|------------:|--------:|
| 256      | 1043.4   | 1031.5 | 1.011   | 19.2  | 1088.0      | 1118.6  |
| 4096     | 1060.5   | 1069.1 | 0.992   | 51.0  | 1161.5      | 1156.0  |
| 65536    | 1676.6   | 1664.9 | 1.007   | 646.8 | 1735.3      | 1850.6  |
| 262144   | 3476.7   | 3535.2 | 0.983   | 2368.0| 3999.4      | 3897.0  |
| 1048576  | 13028.9  | 12522.4| 1.040   | 11792.4| 13319.7    | 15705.2 |
| 4194304  | 46155.7  | 46054.8| 1.002   | 44719.5| 52702.2    | 57950.0 |

(The `fl size=16` row reads ~44 ns because that first benchmark executed before
the membrane pipeline finished lazy init and fell through to `native_libc_calloc`;
it is an init artifact, not a representative membrane figure, and is excluded.)

new/old ratio band is 0.98–1.04 across all sizes → NEUTRAL by the ledger
(`0.95–1.05`), with the 1 MiB point a slight loss. No measured win exists to keep.

## Secondary finding (not this lever's target)

The membrane allocator carries a large fixed overhead vs glibc for small
allocations: at 256 B, fl `calloc` p50 ≈ 1043 ns vs glibc ≈ 19 ns (~54x). This is
the safety-membrane cost (fingerprint header + trailing canary + page-oracle
registration + runtime-policy decide/observe), a by-design safety/perf tradeoff,
not a memset artifact. Even glibc's theoretical ceiling is only ~3–6% faster than
`fl_old` at ≥1 MiB, so the *entire* achievable upside of any calloc zero-skip is
small and confined to huge allocations.

## Retry predicate

Do **not** re-attempt the plain `alloc_zeroed` form — it is structurally blocked by
the arena's `align >= 32` requirement vs Rust `MIN_ALIGN = 16`. The only path to a
real (but ≤ ~6%, ≥1 MiB-only) win is to decouple the arena's *header offset* from
its *layout alignment*: request `Layout::from_size_align(total, 16)` (≤ MIN_ALIGN, so
`alloc_zeroed` → libc `calloc`) while keeping a 32-byte header offset so `user_base`
stays 16-aligned (POSIX/`max_align_t`-conformant; calloc would return 16-aligned
instead of 32-aligned pointers). That changes the arena alignment contract and is
correctness-critical (fingerprint header/canary placement, every arena invariant
that may assume 32-aligned `user_base`), so it must be its own scoped, fully
re-validated bead — and even then the measured ceiling is marginal. Reopen only
with a bench that exercises cold, single-touch large buffers if the upside is
judged worth the contract change.
