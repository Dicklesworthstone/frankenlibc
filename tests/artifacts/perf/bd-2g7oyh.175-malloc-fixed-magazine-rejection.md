# bd-2g7oyh.175 malloc fixed-capacity magazine rejection

## Target

`malloc_free_256` was the best unowned non-overlapping residual after the active
`mem.rs`, `str.rs`, and `math/exp.rs` lanes were owned by other agents.

Pass 3 profile on `ts1`:

- `malloc_free_256`: FrankenLibC p50 6.492 ns, mean 8.970 ns; host p50 5.247 ns, mean 6.121 ns
- `malloc_free_64`: FrankenLibC p50 6.740 ns, mean 9.851 ns; host p50 5.768 ns, mean 6.909 ns
- `malloc_free_large`: FrankenLibC p50 9.038 ns, mean 9.940 ns; host p50 31.889 ns, mean 37.439 ns

## Candidate

One lever: replace each `ThreadCache` magazine's `Vec<usize>` with fixed
`[usize; MAGAZINE_CAPACITY] + len` LIFO storage.

Alien primitive: graveyard section 7.9 modern allocator design, specifically
fixed-capacity slab/magazine storage for hot small bins.

## Behavior Proof

RCH command:

```bash
RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-175-proof cargo test -p frankenlibc-core malloc -- --nocapture --test-threads=1
```

Result: passed on `ts1`.

- 63 focused malloc unit tests passed
- `malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable` passed
- `allocator_properties::prop_malloc_state_tracks_large_allocation_metadata` passed

Isomorphism:

- Ordering preserved: yes; pop remains LIFO and drain returns push order.
- Tie-breaking unchanged: N/A.
- Floating-point unchanged: N/A.
- RNG unchanged: N/A.
- Golden output: lifecycle SHA test passed.

## Same-Head A/B

Both runs used `HEAD=71f9f91d` on `ts1`, sample size 50, warm-up 1s,
measurement 3s.

Clean baseline:

- `malloc_free_64`: p50 6.166 ns, mean 8.168 ns
- `malloc_free_256`: p50 6.360 ns, mean 7.198 ns
- `malloc_free_large`: p50 8.942 ns, mean 9.635 ns

Candidate:

- `malloc_free_64`: p50 7.657 ns, mean 9.315 ns
- `malloc_free_256`: p50 6.637 ns, mean 7.880 ns
- `malloc_free_large`: p50 10.113 ns, mean 10.691 ns

## Verdict

Reject and restore. The candidate is proof-clean but regresses the target and
both guard rows on same-worker, same-HEAD RCH evidence.

Score: `(Impact 0 * Confidence 4) / Effort 2 = 0.0`.

Next allocator route should not be another magazine storage micro-lever. Move
deeper into the central-bin/thread-cache interaction or TLSF-style bitmap class
selection only after a fresh allocator-specific profile identifies that path.
