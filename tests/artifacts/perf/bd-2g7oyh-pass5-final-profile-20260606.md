# bd-2g7oyh: Pass 5 final shifted profile

## Command

RCH worker: `ts1`

```
RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass5-final-profile \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench \
  -- 'glibc_baseline_(memcmp_4096|memchr_absent|memmove_4096|memcpy_4096|memset_4096|malloc_free_64|malloc_free_256|malloc_free_large|qsort_128_i32)' \
  --noplot --sample-size 35 --warm-up-time 1 --measurement-time 3
```

## Rows

| profile | FrankenLibC p50 | FrankenLibC mean | Host p50 | Host mean | note |
|---|---:|---:|---:|---:|---|
| `memcpy_4096` | 49.940 ns | 52.447 ns | 48.130 ns | 49.803 ns | small gap |
| `memset_4096` | 41.887 ns | 46.524 ns | 39.939 ns | 40.622 ns | small-to-moderate mean gap |
| `memcmp_4096` | 63.441 ns | 71.921 ns | 48.789 ns | 50.793 ns | repeated micro-levers rejected; route deeper |
| `malloc_free_64` | 7.426 ns | 17.280 ns | 5.429 ns | 6.614 ns | largest mean/tail gap in this profile |
| `malloc_free_256` | 6.313 ns | 12.543 ns | 5.900 ns | 7.214 ns | mean/tail gap |
| `malloc_free_large` | 9.224 ns | 10.112 ns | 32.220 ns | 38.653 ns | FrankenLibC ahead |
| `qsort_128_i32` | 1868.731 ns | 2188.781 ns | 2664.165 ns | 2798.456 ns | FrankenLibC ahead |
| `memmove_4096` | 46.598 ns | 48.427 ns | 43.802 ns | 51.969 ns | p50 gap, mean ahead |
| `memchr_absent` | 32.252 ns | 34.155 ns | 21.735 ns | 23.729 ns | still a scan gap after accepted indexed pass |

## Next primitive

Created open bead `bd-2g7oyh.189`: `malloc_free_64` segregated hot slab tail flattening.

Rationale: repeated `memcmp` micro-levers have failed the keep gate. The profile still shows string scan gaps, but the cleanest non-retry structural target is allocator tail flattening: `malloc_free_64` has a mean gap of `17.280 ns` vs host `6.614 ns` and p95/p99 tail excess. The next pass should attack per-thread hot slab / central-bin interaction / TLSF-style bitmap class selection, not fixed-capacity magazine storage, which was already rejected by same-worker A/B.

The next bead must preserve allocation/free accounting, pointer reuse contracts, lifecycle record count/order/fields, and golden transcript sha256.
