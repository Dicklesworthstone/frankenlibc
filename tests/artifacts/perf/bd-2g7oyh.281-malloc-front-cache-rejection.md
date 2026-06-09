# bd-2g7oyh.281 malloc front-cache metadata rejection

## Target

`malloc_free_256` was re-opened as a structural small-allocation residual after a
pass-25 focused row reported a stronger gap on current `origin/main`.

Clean same-worker baseline was refreshed on `vmi1227854` from detached worktree
`/data/projects/.scratch/frankenlibc-bd281-bitset-baseline-20260609T1408`,
`HEAD=b6b2ff0a`.

Criterion estimates from
`/data/tmp/frankenlibc-bd281-bitset-remote-baseline-20260609T1416`:

| row | impl | median ns | mean ns |
|---|---|---:|---:|
| `malloc_free_64` | FrankenLibC | 6.232 | 6.318 |
| `malloc_free_64` | host glibc | 5.036 | 4.707 |
| `malloc_free_256` | FrankenLibC | 6.161 | 6.211 |
| `malloc_free_256` | host glibc | 4.318 | 4.296 |

## Candidate

One structural front-cache metadata lever was attempted in
`crates/frankenlibc-core/src/malloc/allocator.rs`:

- first draft: compact hot-slot bitset plus an affine lease for exact local-cache
  malloc/free cycles;
- narrowed draft: compact hot-slot bitset only, with the original free-path
  ordering restored.

No source was kept.

## Behavior proof while evaluating

Local focused checks with private target
`/data/tmp/frankenlibc-bd281-local-target`:

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs`: passed
- `git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs`: passed
- `cargo test -p frankenlibc-core malloc --lib -- --nocapture --test-threads=1`: passed, 65/65
- `cargo test -p frankenlibc-core --test property_tests allocator_properties::prop_malloc_state_tracks_large_allocation_metadata -- --nocapture --test-threads=1`: passed
- `cargo check -p frankenlibc-core --lib`: passed

`cargo clippy -p frankenlibc-core --lib -- -D warnings` remains blocked by
pre-existing unrelated lints in `math/exp.rs`, `stdlib/sort.rs`,
`string/fnmatch.rs`, and `string/regex.rs`.

## Performance result

The affine-lease draft was rejected on local sanity before remote scoring:
`malloc_free_256` printed `p50=8.649 ns`, `mean=11.088 ns`, clearly worse than
the clean local baseline shape.

The narrowed bitset-only draft was not a credible keep either:

- local sanity: Criterion center around `6.607 ns` for `malloc_free_256`; the
  custom GLIBC_BASELINE print reported `p50=6.774 ns`, `mean=8.741 ns`;
- attached scratch RCH run selected `vmi1227854` but detached after crates-index
  update and left only `.rustc_info.json` in the scratch `.rch-target`, so it
  produced no candidate estimates;
- the only completed follow-up remote estimates came from the shared
  `/data/projects/frankenlibc` tree, not the edited scratch tree, and were worse
  than the clean baseline (`malloc_free_256` FrankenLibC median `6.630 ns`, mean
  `6.683 ns`).

## Verdict

Rejected and restored. The front-cache bitset/lease family is proof-clean but
does not clear the keep gate on available same-worker evidence.

Score: `0.0`.

Next allocator route should not retry hot-slot representation or exact-cycle
lease metadata as a standalone lever. The remaining gap likely needs the deeper
structural route already identified in `bd-4scbmf`: a flat/index-linked
small-object cache or a broader hot/cold split that reduces cache operations and
observability bookkeeping together.
