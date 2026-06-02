# bd-iskiih wcsrchr eight-wide skip proof

## Target

Fresh profile-backed target after the ready `[perf]` queue was drained:
`wcsrchr` non-NUL absent scans in `crates/frankenlibc-core/src/string/wide.rs`.

Baseline command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench wcsrchr_absent -- --sample-size 50 --noplot
```

Baseline rch job: `29869223945702214` on `vmi1156319`.

| Bench | p50 ns/op | p95 ns/op |
|---|---:|---:|
| `wcsrchr_absent_16` | 11.858 | 21.250 |
| `wcsrchr_absent_64` | 44.377 | 72.750 |
| `wcsrchr_absent_256` | 171.729 | 234.719 |
| `wcsrchr_absent_1024` | 695.376 | 866.829 |
| `wcsrchr_absent_4096` | 2656.009 | 3242.828 |

## Alien primitive recommendation card

- Symptom: scalar branch-heavy wide-character scan remains slower than the upstream C SIMD/string-scan incumbent on long absent searches.
- Graveyard route: constants/cache/SIMD scan family; use safe Rust autovectorization-friendly block tests before exact resolution.
- Primitive: skip clean fixed-width blocks that contain neither the target wide character nor NUL, then resolve only candidate blocks in original order.
- EV: Impact 4 x Confidence 5 x Reuse 4 / Effort 1 x AdoptionFriction 1 = 80.0.
- Fallback trigger: reject and restore the previous four-lane loop if the post-rch p50 regresses at any measured size or if the golden test-line hash changes.

## One lever

The only source lever is the `c != 0` loop shape:

- Previous loop resolved every four-wide chunk lane-by-lane.
- New loop loads eight wide characters and skips the chunk when all lanes are neither `0` nor `c`.
- Candidate chunks still resolve lane-by-lane from lowest to highest index.
- The `c == 0` branch is unchanged.

## Isomorphism proof

- NUL ordering is preserved: each candidate chunk checks lane `k` for NUL before considering lane `k + 1`, so bytes after a terminator are still ignored.
- Last-match tie-breaking is preserved: matching lanes before the terminator update `last` in increasing index order, so the final value is the greatest matching index before NUL.
- Unterminated slices are preserved: when no NUL is present, the scan still covers every element and returns the greatest matching index or `None`.
- `c == 0` behavior is preserved exactly because that branch was not modified; it still returns the first terminator index or `s.len()` for unterminated input.
- Floating-point and RNG behavior are unaffected; the function only performs integer comparisons over a borrowed `u32` slice and does not touch global state.

## Golden behavior

Pre-edit direct rch test command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core wcsrchr -- --nocapture
```

Pre-edit result: 5/5 existing `wcsrchr` tests passed via rch job `29869223945702232` on `vmi1153651`.

Existing test-line sha256:

```text
310fdc0bccac74f6e2a12ba0d659608176e5715caec577bd54b6365f164028a2
```

The post-edit gate must preserve that hash for the five pre-existing `wcsrchr` test lines and pass the added skipped-chunk regression.

Post-edit direct rch test command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core wcsrchr -- --nocapture
```

Post-edit result: 6/6 `wcsrchr` tests passed via rch job `29869223945702259` on `vmi1149989`.

Existing five-line sha256 remained:

```text
310fdc0bccac74f6e2a12ba0d659608176e5715caec577bd54b6365f164028a2
```

Full six-line post-edit sha256:

```text
fd2bde19273a0dea5b7c0b6526135f3470f4eeebc5764f5b259eb9a34043e258
```

## Post-benchmark

Post command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench wcsrchr_absent -- --sample-size 50 --noplot
```

Post rch job: `29869223945702271` on `vmi1149989`.

| Bench | Before p50 ns/op | After p50 ns/op | Delta |
|---|---:|---:|---:|
| `wcsrchr_absent_16` | 11.858 | 8.122 | -31.5% |
| `wcsrchr_absent_64` | 44.377 | 19.535 | -56.0% |
| `wcsrchr_absent_256` | 171.729 | 71.502 | -58.4% |
| `wcsrchr_absent_1024` | 695.376 | 381.399 | -45.1% |
| `wcsrchr_absent_4096` | 2656.009 | 1213.134 | -54.3% |

Score: Impact 4 x Confidence 5 / Effort 1 = 20.0.

## Validation

- `TMPDIR=/data/tmp cargo fmt -p frankenlibc-core --check`: passed locally because `rch` refuses non-compilation fmt commands.
- `git diff --check -- crates/frankenlibc-core/src/string/wide.rs .skill-loop-progress.md tests/artifacts/perf/bd-iskiih-wcsrchr-eight-wide-skip.md`: passed locally.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core wcsrchr -- --nocapture`: passed.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets`: passed via rch job `29869223945702282` on `vmi1153651`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: blocked by unrelated dirty `crates/frankenlibc-core/src/string/mem.rs` edit, `clippy::manual_find` at line 173. `mem.rs` is outside this bead and was not touched or staged for this change.
