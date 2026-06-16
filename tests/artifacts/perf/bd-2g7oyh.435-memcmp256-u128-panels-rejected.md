# bd-2g7oyh.435 - memcmp_256 u128 panel certificate rejection

Date: 2026-06-16
Agent: BoldFalcon
Target: `glibc_baseline_memcmp_256`
Worker: `vmi1227854`

## Profile-backed target

Focused same-worker baseline on pushed head `5f2241258` reproduced a material
`memcmp_256` residual:

- FrankenLibC Criterion: `[3.9937 ns 4.0783 ns 4.1641 ns]`
- FrankenLibC p50/mean: `4.136/4.983 ns`
- Host Criterion: `[3.1850 ns 3.3079 ns 3.4221 ns]`
- Host p50/mean: `3.014/3.683 ns`

The route was selected after `memchr_absent` collapsed on the same worker:
FrankenLibC `24.497/25.567 ns` p50/mean vs host `25.786/28.779 ns`.

## One lever tested and restored

Candidate: replace the exact-256 equality certificate's four 64-byte SIMD
XOR/OR panels with sixteen safe 16-byte native-endian `u128` equality panels.

The helper still only answered "any byte differs." It never decided ordering:
every non-equal case still fell through to the existing bytewise ordered
resolver.

## Behavior proof

RCH focused unit tests while the candidate was present:

```bash
RCH_WORKER=vmi1227854 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  RUST_TEST_THREADS=1 FRANKENLIBC_PROPTEST_CASES=512 \
  cargo test -j 1 -p frankenlibc-core --lib memcmp \
  -- --nocapture --test-threads=1
```

Result: passed 32/32 filtered tests, including:

- `memcmp_exact_16_mask_resolves_first_difference`
- `test_memcmp_exact_256_equal_certificate_guard`
- `test_memcmp_exact_4096_certificate_preserves_ordering`
- `memcmp_golden_output_sha256`
- antisymmetry and std-lexicographic properties
- timingsafe memcmp and wide memcmp guards

RCH property golden:

```bash
RCH_WORKER=vmi1227854 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  RUST_TEST_THREADS=1 FRANKENLIBC_PROPTEST_CASES=512 \
  cargo test -j 1 -p frankenlibc-core --test property_tests \
  golden_memcmp_corpus_sha256 -- --nocapture --test-threads=1
```

Result: passed 1/1 filtered test.

Golden hashes:

- `string::mem::tests::memcmp_golden_output_sha256`: `458c0ae019afaffccbfc5a6aacfeb4713dab611eac4b6257398016a7eae45ef9`
- `string_properties::golden_memcmp_corpus_sha256`: `23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e`

Isomorphism while tested:

- Equal exact-256 buffers returned `Ordering::Equal` only after all 256 bytes
  were proven equal.
- Non-equal exact-256 buffers still used the existing ordered resolver,
  preserving first-difference tie-breaking and unsigned-byte ordering.
- Native-endian conversion was equality-only and unobservable.
- `n` clamping, zero-length behavior, non-256 sizes, exact-16 behavior,
  exact-4096 behavior, FP, RNG, allocation, errno, and locale behavior were
  unchanged.

## Post benchmark

RCH post benchmark on the same worker:

- Candidate FrankenLibC Criterion: `[9.5136 ns 9.6307 ns 9.7615 ns]`
- Candidate FrankenLibC p50/mean: `9.397/12.840 ns`
- Host Criterion: `[3.2274 ns 3.3056 ns 3.3814 ns]`
- Host p50/mean: `3.688/4.376 ns`

Same-worker candidate delta against the baseline:

- p50: `4.136 -> 9.397 ns`, `127.2%` slower
- mean: `4.983 -> 12.840 ns`, `157.7%` slower
- Criterion center: `4.0783 -> 9.6307 ns`, `136.2%` slower

## Verdict

REJECTED-RESTORED.

Score: `0.0`.

Restored source SHA:

- `crates/frankenlibc-core/src/string/mem.rs`: `78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d`

Do not retry the exact-256 `u128` panel family. The next `memcmp_256` attempt
needs a materially different generated/backend-dispatch primitive or a compiler
lowering change, not more safe native-word paneling.
