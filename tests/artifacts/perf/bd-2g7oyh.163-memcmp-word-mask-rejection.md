# bd-2g7oyh.163 memcmp word-mask resolver rejection

## Decision

Reject the SWAR/word-mask first-difference resolver attempted for `memcmp`.
The attempted source change preserved behavior under focused tests, and it
improved the primary `memcmp_16` equal-buffer row, but it repeatedly regressed
the secondary focused `memcmp_256` equal-buffer row on the same RCH worker.
The source changes were restored; this artifact is the only retained output
from the pass.

Score: `(Impact 2 * Confidence 1) / Effort 2 = 1.0`.

## Attempted Lever

One source lever was tried in `crates/frankenlibc-core/src/string/mem.rs`:

- Extract the first differing byte from a mismatched `u64` with `xor` plus
  trailing/leading-zero byte index.
- Use that resolver in the ordered `memcmp` byte resolver and tail word path.
- Add a temporary unit test covering all byte positions in a 32-byte resolver
  panel in both comparison directions.

The temporary source and test edits were removed after the benchmark rejection.

## Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memcmp_16 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Worker: `ts1`

- `glibc_baseline_memcmp_16/memcmp/frankenlibc_core`: samples `78`, p50 `3.881 ns`, p95 `6.875 ns`, p99 `25.000 ns`, mean `5.418 ns`, throughput `258538130.595 ops/s`
- `glibc_baseline_memcmp_16/memcmp/host_glibc`: samples `79`, p50 `2.275 ns`, p95 `3.750 ns`, p99 `15.000 ns`, mean `3.119 ns`, throughput `436957056.304 ops/s`

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memcmp_256 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Worker: `ts1`

- `glibc_baseline_memcmp_256/memcmp/frankenlibc_core`: samples `78`, p50 `5.589 ns`, p95 `7.500 ns`, p99 `15.000 ns`, mean `6.483 ns`, throughput `177495321.497 ops/s`
- `glibc_baseline_memcmp_256/memcmp/host_glibc`: samples `78`, p50 `4.001 ns`, p95 `8.750 ns`, p99 `25.000 ns`, mean `5.623 ns`, throughput `250510259.016 ops/s`

## Behavior Proof

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core memcmp -- --nocapture --test-threads=1
```

Worker: `vmi1149989`

Result:

- `30` focused `memcmp` / `timingsafe::memcmp` / `wmemcmp` unit tests passed.
- `string_properties::golden_memcmp_corpus_sha256` passed.
- `string_properties::prop_memcpy_then_memcmp_is_zero` passed.

Golden memcmp corpus sha256:

```text
23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e
```

Formatting:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
```

Result: passed.

## Post Benchmark

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memcmp_16 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Worker: `ts1`

- `glibc_baseline_memcmp_16/memcmp/frankenlibc_core`: samples `79`, p50 `3.438 ns`, p95 `5.625 ns`, p99 `20.000 ns`, mean `4.678 ns`, throughput `296212119.558 ops/s`
- `glibc_baseline_memcmp_16/memcmp/host_glibc`: samples `79`, p50 `2.671 ns`, p95 `3.253 ns`, p99 `20.000 ns`, mean `3.553 ns`, throughput `363985183.548 ops/s`

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memcmp_256 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Worker: `ts1`

- `glibc_baseline_memcmp_256/memcmp/frankenlibc_core`: samples `78`, p50 `6.649 ns`, p95 `8.125 ns`, p99 `20.000 ns`, mean `7.513 ns`, throughput `150736379.064 ops/s`
- `glibc_baseline_memcmp_256/memcmp/host_glibc`: samples `79`, p50 `3.283 ns`, p95 `4.438 ns`, p99 `20.000 ns`, mean `4.206 ns`, throughput `303272278.248 ops/s`

Confirmation command: same as `glibc_baseline_memcmp_256`.

Worker: `ts1`

- `glibc_baseline_memcmp_256/memcmp/frankenlibc_core`: samples `78`, p50 `7.354 ns`, p95 `10.625 ns`, p99 `20.000 ns`, mean `8.813 ns`, throughput `136252344.896 ops/s`
- `glibc_baseline_memcmp_256/memcmp/host_glibc`: samples `78`, p50 `3.867 ns`, p95 `10.000 ns`, p99 `25.000 ns`, mean `5.198 ns`, throughput `258464491.402 ops/s`

## Isomorphism Proof

- Ordering preserved: yes under the attempted edit. The resolver used the first
  non-zero byte in `a_word ^ b_word`, then returned the unsigned comparison of
  exactly `a[index]` and `b[index]`, matching C `memcmp` first-difference
  ordering.
- Tie behavior unchanged: yes under the attempted edit. Equal words continued
  scanning, and fully equal compared regions returned `Ordering::Equal`.
- `n` and length clipping unchanged: yes. The attempted edit did not change
  `count = min(n, a.len(), b.len())`.
- Floating point: N/A.
- RNG: N/A.
- Golden output: unchanged; `golden_memcmp_corpus_sha256` stayed
  `23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e`.

## Rejection Reason

The primary `memcmp_16` row improved, but `memcmp_256` regressed twice on the
same worker after a same-worker baseline:

- Baseline `memcmp_256` Franken p50 `5.589 ns`, mean `6.483 ns`.
- Post `memcmp_256` Franken p50 `6.649 ns`, mean `7.513 ns`.
- Confirmation `memcmp_256` Franken p50 `7.354 ns`, mean `8.813 ns`.

Because `memcmp_256` is an explicit focused residual in this bead and the
regression repeated, the lever should not be kept. The next memcmp attack
should target the equal-buffer hot path directly rather than a first-difference
resolver that mainly helps mismatch cases.
