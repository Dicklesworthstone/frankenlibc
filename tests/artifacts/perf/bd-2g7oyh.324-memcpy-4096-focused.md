# bd-2g7oyh.324 memcpy_4096 focused gate

Date: 2026-06-10
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

Pass 51 broad profiling on `ovh-a` selected `memcpy_4096` as the cleanest
unowned routing candidate after excluding peer-owned `pow*`/`strncmp` and
freshly rejected `memmove_4096`, `strcpy_4096`, and allocator lanes.

Broad route basis:

| impl | p50 ns | mean ns |
| --- | ---: | ---: |
| FrankenLibC | 42.857 | 56.371 |
| host glibc | 34.214 | 38.631 |

Prior rejected `memcpy` families:

- `bd-2g7oyh.44`: exact full-slice branch before the clamped prefix-copy path.
- `bd-2g7oyh.274`: exact 4096-byte safe portable-SIMD tiled copy.

Any source candidate would have needed a different codegen/alignment/no-overlap
primitive, not another fixed-size copy panel.

## Focused Baseline

Command:

```text
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd324-memcpy4096-baseline-target \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memcpy_4096 --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `ovh-a`.

| impl | criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[44.779 ns 45.220 ns 45.797 ns]` | 45.478 | 49.359 | 57.125 | 100.500 |
| host glibc | `[41.795 ns 42.502 ns 43.195 ns]` | 41.851 | 47.104 | 45.859 | 68.875 |

Focused gap: `1.087x` p50 and `1.048x` mean. Absolute p50 gap: `3.627 ns`.

## Isomorphism

No source code changed.

- Copied prefix count `min(n, dest.len(), src.len())`: unchanged by construction.
- Destination tail behavior: unchanged by construction.
- Non-overlap `memcpy` contract: unchanged by construction.
- Ordering/tie-breaking: not involved.
- Floating point/RNG: not involved.
- Source SHA-256:
  - `crates/frankenlibc-core/src/string/mem.rs`
    `561924f9cec259aaeb5f38c20cc40325b18b6eea2a2ca52cf6d3cb1ea78d79dd`
- Fixture SHA-256:
  - `tests/conformance/fixtures/string_memory_full.json`
    `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
  - `tests/conformance/fixtures/memcpy_strict.json`
    `6bdd6fb00bff508d07eb985bdc7c258a1a10f8ea96de72cf7e392483e886c233`

## Verdict

NO-CODE REJECTED. Score `0.0`.

The focused same-worker gap collapsed below the edit gate, so source work would
not be profile-backed. Reprofile and attack the next reproduced unowned
residual. Only return to `memcpy_4096` with a material focused gap and a
structurally different codegen/alignment/no-overlap primitive.
