# bd-2g7oyh.159 - strchr homogeneous-run certificate rejection

## Target

- Bead: `bd-2g7oyh.159`
- Symbol/workload: `glibc_baseline_strchr_absent`, 4096-byte all-`a` C string scanning for absent `z`
- Profile source: RCH `ts2` discovery, then focused Criterion baseline
- Candidate primitive: homogeneous-run block certificate. For a 256-byte block whose first byte is neither NUL nor the needle, prove the whole block is the same byte with safe SIMD `block_has_non_byte_256`; if certified, skip it, otherwise fall back to the existing ordered byte-or-NUL resolver.

## Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-159-baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strchr_absent --warm-up-time 1 --measurement-time 3 --sample-size 30
```

Worker: `ts2`

- FrankenLibC: p50 `63.951 ns`, p95 `77.750 ns`, p99 `109.778 ns`, mean `67.719 ns`
- Host glibc: p50 `48.612 ns`, p95 `62.750 ns`, p99 `85.000 ns`, mean `52.702 ns`

## Proof

Command:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-159-proof cargo test -p frankenlibc-core strchr -- --nocapture --test-threads=1
```

Worker: `ts2`

Result: passed. The focused lane ran 13 `strchr`/`strchrnul` unit tests, including the two new homogeneous-run tests in the scratch experiment, plus `string_properties::prop_strchr_strrchr_both_find_or_miss`.

Golden fixture SHA256 values were unchanged because the change was not kept:

```text
a70dc7fad4679910cf938a65e8a18b3fec0823d9c739f931345624e0b406bdc1  tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json
65311119dd6d169d9584ed825329f856739cf66b76a1c431eb7417dd56ece845  tests/conformance/fixtures/string_memory_hotpaths_wave10.json
```

## Re-benchmark

Command:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-159-post cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strchr_absent --warm-up-time 1 --measurement-time 3 --sample-size 30
```

Worker: `ts2`

- FrankenLibC: p50 `63.379 ns`, p95 `75.250 ns`, p99 `105.500 ns`, mean `66.580 ns`
- Host glibc: p50 `48.693 ns`, p95 `67.393 ns`, p99 `95.000 ns`, mean `52.581 ns`

## Isomorphism

- Ordering preserved: yes. Certified blocks are skipped only when every byte in the block equals a byte that is neither NUL nor the needle. Mixed blocks fall back to the existing scalar first-stop resolver.
- Tie-breaking unchanged: yes. A returned index is still resolved by scanning bytes in increasing order; the certificate path only skips blocks with no possible return index.
- Floating-point: N/A.
- RNG: N/A.
- Golden outputs: unchanged; no golden files were edited.

## Decision

Rejected/restored. Same-worker improvement was only `63.951 ns -> 63.379 ns` p50 and `67.719 ns -> 66.580 ns` mean. This is below the Score>=2.0 keep gate, so no source change was applied to `main`.

Next deeper primitive: stop iterating `find_byte_or_nul` folded scan micro-levers. Re-profile and attack a different residual, likely `strcmp_256_equal` exact equal-prefix dispatch or `memcpy_4096` copy-kernel structure, whichever is top and unreserved after the next RCH profile.
