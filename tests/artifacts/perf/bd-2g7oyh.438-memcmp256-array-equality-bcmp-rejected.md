# bd-2g7oyh.438 - memcmp_256 array equality libcall rejection

Date: 2026-06-16
Agent: BoldFalcon
Worker: `vmi1227854`
Target: `glibc_baseline_memcmp_256`
Verdict: REJECTED-RESTORED
Score: 0.0

## Profile-backed Baseline

Focused same-worker baseline command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass141-memcmp256-baseline-target-20260616T0342 CRITERION_HOME=/data/tmp/frankenlibc-pass141-memcmp256-baseline-criterion-20260616T0342 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memcmp_256 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Results:

- FrankenLibC Criterion: `[4.5134 ns 4.5958 ns 4.6746 ns]`
- FrankenLibC profile line: p50 `4.683 ns/op`, mean `7.280 ns/op`
- Host Criterion: `[3.4145 ns 3.4313 ns 3.4479 ns]`
- Host profile line: p50 `3.438 ns/op`, mean `4.493 ns/op`

The focused same-worker gap reproduced a material exact-256 residual.

## Candidate

One lever only: replace the exact `count == 256` equality certificate with a
safe array-reference equality helper:

```rust
if count == MEMCMP_EXACT_256_BYTES && memcmp_exact_256_array_equal(a, b) {
    return Ordering::Equal;
}
```

The candidate used `<&[u8; 256]>::try_from(...)` for both slices, then compared
the arrays for equality. It removed the prior explicit `ne_simd_folded_256`
helper while the candidate was present.

## Behavior Proof

RCH focused unit proof while the candidate was present:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS,RUST_TEST_THREADS rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass141-memcmp256-proof-target-20260616T0345 cargo test -j 1 -p frankenlibc-core --lib memcmp -- --nocapture --test-threads=1
```

Result: passed 32/32 filtered tests while the candidate was present, including:

- `memcmp_golden_output_sha256`
- exact 16/256/4096 guards
- first-difference ordering
- antisymmetry and lexicographic properties
- timingsafe memcmp
- wide memcmp

Golden SHA:

```text
memcmp_golden_output_sha256 = 458c0ae019afaffccbfc5a6aacfeb4713dab611eac4b6257398016a7eae45ef9
```

The broader property corpus was not rerun after the candidate failed the codegen
gate. The current accepted property golden for this lane remains:

```text
golden_memcmp_corpus_sha256 = 23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e
```

Isomorphism while tested:

- Equal exact-256 buffers returned `Ordering::Equal` only after the full 256-byte
  window compared equal.
- Every non-equal exact-256 buffer fell through to the existing ordered resolver,
  preserving first-difference tie-breaking and unsigned-byte ordering.
- `n` clamping, zero-length behavior, non-256 sizes, exact-16 behavior,
  exact-4096 behavior, floating-point behavior, RNG behavior, allocation
  behavior, errno, and locale were unchanged.

## Codegen Rejection

The candidate was rejected before post-benchmark because the generated LLVM IR
lowered the exact-256 equality check to an external `bcmp` libcall. That violates
the safe-Rust no-C-libcall primitive requirement for this lane.

Codegen command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS,RUSTFLAGS rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass141-memcmp256-codegen-target-20260616T0349 RUSTFLAGS=--emit=llvm-ir,asm cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

Generated artifact:

```text
/data/tmp/frankenlibc-pass141-memcmp256-codegen-target-20260616T0349/release/deps/frankenlibc_core-23eb28dedea95ec2.ll
```

Relevant IR:

```text
174938: ; frankenlibc_core::string::mem::memcmp
174940: define ... string3mem6memcmp(...)
175000: %bcmp.i = tail call i32 @bcmp(ptr noundef nonnull dereferenceable(256) %a.0, ptr noundef nonnull dereferenceable(256) %b.0, i64 256)
175001: %6 = icmp eq i32 %bcmp.i, 0
```

The module also declares `@memcmp` and `@bcmp`, but the decisive rejection is the
`@bcmp(..., i64 256)` call in `frankenlibc_core::string::mem::memcmp`.

## Restoration

The candidate source was manually restored after codegen rejection.

```text
git diff -- crates/frankenlibc-core/src/string/mem.rs
# empty

sha256sum crates/frankenlibc-core/src/string/mem.rs
78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d  crates/frankenlibc-core/src/string/mem.rs
```

## No-retry Route

Do not retry array-reference equality for `memcmp_256`; LLVM lowers it to
`bcmp` on the profiled build. Also do not retry the previous slice-lexicographic,
foldback/two-128, wrapper inline, or safe native-word panel families.

Future `memcmp_256` work needs a self-contained generated load/test sequence or
a compiler-lowering primitive that proves no `bcmp`/`memcmp` external call before
benchmarking.
