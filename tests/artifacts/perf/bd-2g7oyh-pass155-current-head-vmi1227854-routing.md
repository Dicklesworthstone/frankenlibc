# bd-2g7oyh.438 - pass 156 current-head broad routing profile

Date: 2026-06-16
Agent: BoldFalcon
Worker: RCH `vmi1227854`
Status: routing evidence only

## Target

The pass 148 residual queue had been consumed or invalidated by focused gates:

- `strlen_4096`: focused gap reproduced but no RCH-compatible codegen artifact.
- `exp10f`: focused gate reversed, FrankenLibC faster.
- `exp10`: focused gate collapsed.
- `erfc`: focused gates collapsed twice.
- `memchr_absent`: peer rejected/restored current-head candidate.
- `memmove_4096`: focused gate routed out after current source screen.
- `memcpy_4096`: focused gate collapsed to near parity.

Pass 156 therefore reprofiled current head broadly before selecting the next
hotspot.

## Command

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass155-broad-vmi1227854 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_ --noplot --sample-size 40 --warm-up-time 0.5 \
  --measurement-time 2
```

RCH completed successfully on `vmi1227854` in about `655 s`.

## Material Slower Rows

| row | FrankenLibC p50/mean ns | host p50/mean ns | ratio p50/mean | route |
| --- | ---: | ---: | ---: | --- |
| `strcpy_4096` | `61.877 / 61.517` | `44.799 / 47.243` | `1.381x / 1.302x` | Next focused gate. Largest current absolute string gap. |
| `malloc_free_64` | `6.509 / 8.252` | `3.922 / 6.303` | `1.660x / 1.309x` | Tiny-ns hot-cycle lane; prior exact hot-slot families exhausted. Multi-object/cache-pressure row is faster than host. |
| `malloc_free_256` | `5.544 / 6.929` | `3.625 / 5.317` | `1.529x / 1.303x` | Same allocator caveat as above. |
| `memcmp_256` | `4.840 / 8.566` | `3.715 / 5.126` | `1.303x / 1.671x` | Small absolute row with multiple exact-size rejects; not first target. |
| `printf_g_6` | `154.628 / 159.964` | `129.916 / 131.583` | `1.190x / 1.216x` | Moderate; prior focused gate collapsed. |
| `strlen_4096` | `25.750 / 29.257` | `21.606 / 23.944` | `1.192x / 1.222x` | Needs codegen/backend artifact; not another scan-shape guess. |
| `memmove_4096` | `33.957 / 36.564` | `28.750 / 31.626` | `1.181x / 1.156x` | Just routed out in pass 153. |
| `memchr_absent` | `28.187 / 31.967` | `24.970 / 27.015` | `1.129x / 1.183x` | Peer current-head rejection; avoid duplicate work. |

## Faster Or Closed Rows

`memcpy_4096`, `memset_4096`, `strcmp_256_equal`, `strchr_absent`,
`strrchr_absent`, `strncmp_256_equal`, `strspn_long`, `strpbrk_absent`,
`memmem_absent`, `strstr_absent`, `strcasestr_absent`, `wcsstr_absent`,
`fnmatch_*`, `qsort_128_i32`, `scanf_*`, `strtol*`, `strtoul*`, allocator
cache-pressure/large, and most math rows were faster than host or not credible
first targets under the current queue.

## Route

Open a fresh focused `strcpy_4096` gate next. A source edit is admissible only
if the focused same-worker RCH baseline reproduces a material p50+mean gap and
the lever is structurally different from the no-repeat families:

- word/SWAR/global NUL certificates;
- prefix-helper attributes and cold splitting;
- scalar terminal splitting;
- exact dispatch hoists;
- array-copy lowering and typed exact-source/destination lowering;
- public-wrapper inlining;
- repeated SIMD copy-store variants;
- scan-only certificate plus one bulk copy;
- uniform-source/certified-block copy-shape retunes.

The next valid primitive is a generated/backend-dispatch terminal/no-overlap
strategy or an ABI/codegen specialization with an explicit first-NUL and
tail-no-overwrite proof.

## Behavior Proof

No production source changed. Behavior is unchanged by identity.
