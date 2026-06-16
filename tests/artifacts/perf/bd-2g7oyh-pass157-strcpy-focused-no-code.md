# bd-2g7oyh.439 - pass 157 strcpy_4096 focused no-code closeout

Date: 2026-06-16
Agent: BoldFalcon
Worker: RCH `vmi1153651` (admitted worker)
Status: no-code route-out

## Target

Pass 156 broad routing selected `strcpy_4096` as the largest current string
residual:

| source | FrankenLibC p50/mean ns | host p50/mean ns |
| --- | ---: | ---: |
| Pass 156 broad, `vmi1227854` | `61.877 / 61.517` | `44.799 / 47.243` |

The focused gate requested `vmi1227854`, but RCH admitted the job on
`vmi1153651`. The result is still a valid focused gate for deciding whether a
source edit is worth considering, provided any post-edit benchmark would use the
same admitted worker.

## Focused Baseline

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass157-strcpy-baseline-vmi1227854 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 80 --warm-up-time 1 \
  --measurement-time 3
```

RCH completed on `vmi1153651` in `437.8 s`.

| row | Criterion interval ns | p50 ns | mean ns |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[115.70, 119.37, 123.72]` | `120.009` | `137.883` |
| host glibc | `[105.69, 107.88, 110.42]` | `105.642` | `110.936` |

Focused ratio: `1.136x` p50 and `1.243x` mean.

## Source Screen

Current `crates/frankenlibc-core/src/string/str.rs` SHA-256:

```text
807aac872b3bd7b4ec24b3819a59632a15f8abfee521a94613c554084cad6ddd
```

Current source already has a retained exact `4096 + NUL` specialization:

- eight 512-byte safe-SIMD NUL certificate probes over the first 4096 bytes;
- early-NUL fallback that copies only through the first NUL and preserves the
  destination tail;
- no-early-NUL terminal path that copies the whole 4097-byte source.

The pass 145 codegen screen remains directly applicable: the current no-early-
NUL path already lowers to a terminal `llvm.memcpy(..., i64 4097, false)`.
Codegen artifact SHA-256:

```text
9bb595bb058efe49454f3aeae68e36ffcba057bcc0f812ec8b912b313eaecfc1
```

## No-Repeat Families

No source lever was applied because the available manual edits repeat prior
closed families:

- word/SWAR and global NUL certificates;
- prefix-helper attributes and cold splitting;
- terminal splitting and scalar terminal-NUL splitting;
- exact dispatch hoists;
- array-copy lowering and typed exact-source/destination lowering;
- public-wrapper inlining;
- repeated SIMD copy-store variants;
- scan-only certificate plus one bulk copy;
- uniform-source/certified-block copy-shape retunes.

The next valid route for `strcpy_4096` is not another manual scan/copy retune.
It needs a genuinely different generated/backend-dispatch terminal/no-overlap
primitive or compiler-lowering proof.

## Behavior Proof

No production source changed. Behavior is unchanged by identity: first-NUL
selection, copied byte order, returned byte count, too-small-destination panic
behavior, destination tail preservation after early NUL, floating-point state,
RNG state, allocation behavior, errno, locale, and existing golden outputs are
untouched.

Existing `test_strcpy_golden_transcript_sha256` value remains the known
unchanged contract:

```text
fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401
```

## Verdict

NO-CODE ROUTE-OUT. Score `0.0`.

Next profile-backed route: focus `printf_g_6` from the pass 156 broad profile
before any source work. The allocator rows are tiny-ns hot-cycle residuals with
prior exact-slot families exhausted, while `memcmp_256`, `strlen_4096`,
`memmove_4096`, and `memchr_absent` are current no-repeat or peer-rejected
lanes.
