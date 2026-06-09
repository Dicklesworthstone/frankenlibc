# bd-2g7oyh.290 malloc LIFO/slab reroute

## Target

Fresh pass after `bd-2g7oyh.283` no-code rejection and an empty ready perf
queue. Existing artifacts `bd-4scbmf-malloc-structural-analysis.md` and
`bd-2g7oyh.281-malloc-hot-cycle-structural.md` identified the next allocator
primitive as an intrusive safe-Rust index-linked small-object LIFO/slab plus
deferred hot-path counters.

No allocator source edit was made before the fresh RCH profile gate.

## Fresh RCH profile

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass27-profile-20260609 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_(memcpy_4096|memset_4096|strlen_4096|strcmp_256_equal|memcmp_4096|malloc_free_64|malloc_free_256|malloc_free_large|qsort_128_i32|strchr_absent|strncmp_256_equal|strncasecmp_256_equal|memmove_4096|strrchr_absent|strcpy_4096|memchr_absent|strspn_long|strpbrk_absent|strcasestr_absent|memmem_absent|strstr_absent|pow_irrational|powf_irrational|exp10f)' \
  --noplot --sample-size 20 --warm-up-time 1 --measurement-time 2
```

RCH selected worker `ovh-a`. Criterion estimates were written under
`/data/tmp/frankenlibc-pass27-profile-20260609/criterion`.

Top rows by FrankenLibC/host median ratio:

| row | fl p50 ns | host p50 ns | p50 ratio | fl mean ns | host mean ns | mean ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `memchr_absent` | 27.026 | 17.792 | 1.519x | 27.026 | 17.905 | 1.509x |
| `strlen_4096` | 24.041 | 17.508 | 1.373x | 24.070 | 17.630 | 1.365x |
| `strcpy_4096` | 47.108 | 37.389 | 1.260x | 48.286 | 38.857 | 1.243x |
| `memmove_4096` | 35.445 | 29.567 | 1.199x | 35.457 | 29.547 | 1.200x |
| `memset_4096` | 35.662 | 30.804 | 1.158x | 35.667 | 31.190 | 1.144x |
| `malloc_free_64` | 5.023 | 4.364 | 1.151x | 5.045 | 4.367 | 1.155x |
| `malloc_free_256` | 5.007 | 4.369 | 1.146x | 5.013 | 4.376 | 1.146x |

## Verdict

No-code reroute, Score `0.0` for this allocator bead.

The allocator residual exists, but the fresh profile shows it is not the current
top reproduced gap and is much smaller than the string absence rows. No
ordering, tie-breaking, floating-point, RNG, allocator lifecycle, or golden
outputs changed because no source was edited.

Next target: file and baseline a fresh `memchr_absent` bead. Prior memchr
micro-families remain off-limits unless the focused same-worker baseline
reproduces this fresh top gap and the next primitive is structurally different.
