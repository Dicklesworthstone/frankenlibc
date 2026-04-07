# Liquid Types Feasibility

`bd-27uz` uses a pragmatic first step instead of waiting on full Flux adoption.

## What Landed

- `BoundedIndex<const MAX: usize>` now provides a `#[repr(transparent)]` wrapper for allocator table indexes.
- `SizeClassIndex` applies that wrapper to the 32-entry small-allocation table.
- Thread-cache magazine lookups and central-bin accesses convert raw `usize` inputs once at the boundary, then use the bounded wrapper for the internal array access sites.
- `crates/frankenlibc-core/build.rs` emits `target/bounds_audit.json` so the converted sites are visible in build artifacts.

## Why This Is The Right First Step

- The allocator already has a compact, fixed-cardinality indexing surface, so const-generic wrappers fit naturally.
- We get immediate removal of repeated ad hoc bounds checks at the internal access sites without introducing a research-only toolchain dependency.
- The wrapper is ABI-neutral because it is transparent over `usize`.

## Flux Assessment

- Flux is still a useful direction for proving caller-side predicates like `n <= dst.len()` in string and allocator hot paths.
- It is not a good gate for this repo today because it would add a second proof toolchain to an already nightly-only workspace.
- The manual wrapper approach keeps the proof obligation local, reviewable, and cheap to benchmark.

## Next Steps

- Extend bounded wrappers to other fixed-cardinality allocator metadata tables once they exist.
- Add optional Flux experiments behind a non-default research path instead of making them part of the main build.
- Promote the bounds audit into release evidence once more allocator surfaces move from dynamic guards to bounded wrappers.
