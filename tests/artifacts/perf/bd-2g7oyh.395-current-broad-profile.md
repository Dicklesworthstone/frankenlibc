# bd-2g7oyh.395 current broad profile

Date: 2026-06-13
Agent: BoldFalcon
Worker: `vmi1227854`
Status: routing evidence only

## Command

```text
RCH_BUILD_SLOTS=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass-current-broad-profile-20260613T2344
CRITERION_HOME=/data/tmp/frankenlibc-pass-current-broad-profile-criterion-20260613T2344
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
--noplot --sample-size 30 --warm-up-time 1 --measurement-time 2
```

RCH selected `vmi1227854`. Remote duration: `742.8s`.

The profile started from `4a012959d`. While the routing run was active, `main`
advanced to `e241390a9`; the intervening commits touched fenv ABI/tests only.
They did not touch `crates/frankenlibc-core/src/string/mem.rs`,
`crates/frankenlibc-core/src/math/exp.rs`,
`crates/frankenlibc-core/src/math/float.rs`,
`crates/frankenlibc-core/src/math/float32.rs`, or
`crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`, so this profile is
usable as routing evidence for those rows on current head.

## Current Residual Rows

| profile | FrankenLibC p50 ns | host p50 ns | p50 ratio | FrankenLibC mean ns | host mean ns | route |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `memcpy_4096` | 40.812 | 30.495 | 1.338x | 42.555 | 33.920 | selected for focused gate |
| `exp10` | 381.467 | 332.071 | 1.149x | 391.031 | 333.009 | focused gate required; prior generated-kernel route rejected |
| `memmove_4096` | 32.500 | 26.768 | 1.214x | 33.255 | 28.963 | keep in routing table; recent codegen/source levers rejected |
| `memcmp_4096` | 49.204 | 42.966 | 1.145x | 52.479 | 44.932 | keep in routing table; needs materially different load/codegen primitive |
| `strncasecmp_256_equal` | 10.907 | 8.695 | 1.254x | 13.423 | 10.970 | lower absolute gap; prior focused gates collapsed |
| `powf_irrational` | 425.459 | 395.158 | 1.077x | 412.408 | 391.620 | lower priority |
| `tanh` | 785.783 | 708.346 | 1.109x | 783.474 | 731.343 | lower priority/noisy |
| `malloc_free_64` | 6.754 | 4.493 | 1.503x | 8.237 | 8.320 | p50-only residual; allocator lane recently collapsed |
| `memset_4096` | 21.150 | 19.094 | 1.108x | 22.412 | 21.923 | too small |
| `memchr_absent` | 23.447 | 20.706 | 1.132x | 27.829 | 29.739 | p50-only residual |
| `strcpy_4096` | 45.557 | 42.850 | 1.063x | 47.471 | 49.874 | p50-only residual |

Rows already faster than host by p50 and mean include `strlen_4096`,
`strcmp_256_equal`, `strncmp_256_equal`, `strchr_absent`, `strrchr_absent`,
`strspn_long`, `strpbrk_absent`, `scanf_*`, `strtol_*`, `strtoul_*`,
`qsort_128_i32`, `printf_f_6`, `exp`, `sin`, `cos`, `log`, `log2`, `exp2`,
`sinh`, `cosh`, `log10`, `expm1`, `cbrt`, `tan`, `atan`, `erf`, `erfc`,
`tgamma`, `lgamma`, `pow`, `pow_half`, `powf_int`, `coshf`, `sinhf`, `tanhf`,
`exp10f`, `log10f`, `expm1f`, `log2f`, `expf_medium`, `exp_wide`, substring
search rows, wide substring rows, fnmatch rows, and wide conversion rows.

## Decision

Run focused gates before any source edit:

1. `memcpy_4096`, because it has the strongest current memory-copy p50/mean
   ratio and prior no-code closeout was on a different worker with a collapsed
   focused gap.
2. `exp10`, because the broad row has the largest absolute non-copy gap but
   prior source attempts require a generated proof-carrying `exp2` primitive
   and must not be retried without focus evidence.

No source code changed for this artifact. Ordering, tie-breaking, floating-point
behavior, RNG, allocation behavior, and golden outputs are unchanged by
construction.

Current-head reference SHAs:

```text
9fd97a8136d1c8fe8e4d09c578da53988c7b5df8906287cc61b167475b19e1fe  crates/frankenlibc-core/src/string/mem.rs
1fee7646337d0954900045ef23d9f3b89c0f30f56986ce06f6d603cdbcfabf94  crates/frankenlibc-core/src/math/exp.rs
0484402c2b45c76023999595dbec00f4af026462f56529a526a78c7c4d044b1f  crates/frankenlibc-core/src/math/float.rs
e7a1c94c56077c386aa43182a7ead70315bc74c6534a256692ad52d3a75567b6  crates/frankenlibc-core/src/math/float32.rs
b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4  tests/conformance/fixtures/string_memory_full.json
27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89  tests/conformance/fixtures/string_ops.json
```
