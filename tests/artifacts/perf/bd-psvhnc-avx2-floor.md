# bd-psvhnc AVX2/FMA target-feature floor

## Profile target

- Bead: `bd-psvhnc`
- Target: residual width gap across safe portable-SIMD string and memory scans.
- Root cause: without an explicit target feature, the x86-64 build targets the baseline
  CPU feature set, so `Simd<u8, 32>`-style kernels lower to narrower code than the host
  glibc AVX2 ifuncs.
- Scope: one build-configuration lever, `.cargo/config.toml`.

## Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- 'strlen|memchr_absent' --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker: `vmi1156319`.

| Bench | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `strlen_4096` | 71.128 | 99.414 | 160.000 | 78.634 |
| `memchr_absent_4096` | 110.715 | 129.913 | 140.000 | 114.557 |

The bead also carried prior same-worker A/B evidence from the cc agent:
`strlen_4096 70.4 -> 25.1 ns` and `memchr_absent_4096 71.5 -> 38.4 ns`.

## Alien primitive

Canonical source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` section 7.7,
SIMD group probes over packed control bytes, generalized to a project-wide vector-width
floor for the existing safe-Rust SIMD scan kernels.

- Primitive: widen existing portable-SIMD execution by selecting an AVX2-capable target
  feature set at compile time.
- Runtime artifact: Cargo build rustflags `-Ctarget-feature=+avx2,+fma`.
- Fallback: reject if RCH post-bench fails Score >= 2.0, if crate-scoped tests diverge,
  or if RCH workers show SIGILL / unsupported CPU behavior.
- EV score: Impact 5 x Confidence 4 / Effort 1 = 20.0.

## One lever

Added:

```toml
[build]
rustflags = ["-Ctarget-feature=+avx2,+fma"]
```

No Rust source changed. The deployment contract changes: produced binaries now require an
AVX2/FMA-capable x86-64 CPU. This matches the owner-approved Option A recorded in
`bd-psvhnc`.

## Isomorphism proof

- Ordering and tie-breaking are unchanged because no Rust control flow, comparison order,
  scalar candidate-resolution path, or public API contract changed.
- Integer/string semantics are unchanged: the existing safe Rust functions still execute
  the same comparisons, NUL handling, bounds, first-match, last-match, and error behavior;
  the compiler may emit wider vector instructions for the same operations.
- Floating-point semantics are unchanged for ordinary Rust arithmetic because Rust does
  not enable fast-math contraction for `a * b + c`; `+fma` only makes fused instructions
  available where Rust semantics already request them, such as `mul_add`.
- RNG behavior is unchanged: no RNG code, seeds, ordering, or state transitions changed.
- Safety posture is unchanged at the Rust level: no `unsafe`, no C BLAS/LAPACK/MKL/XLA,
  and no target-feature-gated unsafe functions were introduced.

## Golden behavior

Pre-change command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core string:: --lib -- --test-threads=1
```

Pre-change result on `vmi1167313`: 397 string tests passed.

Post-change command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core string:: --lib -- --test-threads=1
```

Post-change result on `vmi1293453`: 397 string tests passed.

Stable golden transcript SHA256 over `test ... ok` lines:

```text
007b3407c902798030eb31a0710913baaf9688c2205ab34ec652a278c4537c17
```

## Post benchmark

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- 'strlen|memchr_absent' --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker: `vmi1293453`.

| Bench | Baseline p50 ns/op | Post p50 ns/op | Post p95 ns/op | Post p99 ns/op | Speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| `strlen_4096` | 71.128 | 18.742 | 22.986 | 45.000 | 3.80x |
| `memchr_absent_4096` | 110.715 | 38.514 | 50.000 | 70.000 | 2.88x |

Score: Impact 5 x Confidence 4 / Effort 1 = 20.0, kept.

## Validation

- `git diff --check -- .cargo/config.toml`: passed locally.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core -p frankenlibc-bench --all-targets`: passed on `vmi1149989`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: passed on `vmi1149989`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core -p frankenlibc-bench --all-targets -- -D warnings`: blocked by pre-existing `frankenlibc-bench` literal-cast lints in `benches/string_bench.rs:777-778`; not introduced by this lever.

## Source

- `.cargo/config.toml` SHA256: `d9c649742f4c9e894cf1b839a8207b01a7253ee440a8f06daaa1bcabf1334a8c`
