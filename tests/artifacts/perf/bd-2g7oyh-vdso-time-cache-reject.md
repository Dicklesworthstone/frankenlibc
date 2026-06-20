# bd-2g7oyh: vDSO timing hot-cache reject

Date: 2026-06-20  
Agent: BlackThrush / cod-a  
Worker: `hz2`  
Bench command:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_WORKER=hz2 \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench strtol_glibc_bench -- --noplot
```

`cargo bench` uses Cargo's optimized bench profile; `cargo bench --release` is
not a supported Cargo shape, so the per-crate optimized bench command above was
used.

## Lever

Inspired by read-mostly / kernel-bypass data-plane patterns:

1. Cache resolved vDSO function pointers outside `OnceLock` so timing calls can
   load a direct pointer.
2. Replace per-call vDSO hit `fetch_add` on the `clock_gettime`/`gettimeofday`
   path with buffered thread-local counters.
3. After the clock path regressed, narrow to a `time()`-only cached
   `__vdso_time` pointer.

## Results

Baseline at current head:

| Workload | FrankenLibC | glibc | Ratio |
|---|---:|---:|---:|
| `clock_gettime` | 30.29 ns | 25.43 ns | 1.19x |
| `time` | 3.52 ns | 2.17 ns | 1.63x |

Candidate A, direct vDSO pointer cache plus TLS-buffered hit counters:

| Workload | FrankenLibC | glibc | Ratio | vs baseline |
|---|---:|---:|---:|---:|
| `clock_gettime` | 31.36 ns | 25.43 ns | 1.23x | regression |
| `time` | 2.44 ns | 2.44 ns | 1.00x | gap cut |

Candidate B, `time()`-only direct `__vdso_time` pointer cache:

| Workload | FrankenLibC | glibc | Ratio | vs baseline |
|---|---:|---:|---:|---:|
| `clock_gettime` | 30.29 ns | 25.43 ns | 1.19x | neutral/restored |
| `time` | 3.79 ns | 2.16 ns | 1.75x | regression |

## Decision

Rejected and fully reverted. Candidate A improved `time()` but regressed
`clock_gettime`; candidate B isolated the `time()` cache and still regressed the
target row. Do not retry this family as "cache the resolved vDSO pointer" or
"buffer the hit counter." The residual timing gap needs a different shape, such
as reducing the runtime-ready/pipeline checks around `time(NULL)` without
touching `clock_gettime`, or a measured direct-vvar reader with strict fallback.

## Validation

The full candidate passed focused vDSO conformance before rejection:

```text
cargo test -p frankenlibc-abi --test time_abi_test vdso -- --nocapture
10 passed; 0 failed; 80 filtered out
```

Final source was reverted to the pre-candidate timing ABI, so no timing source
change is shipped from this artifact.

Final reverted-tree validation:

```text
RCH remote vmi1152480:
cargo test -p frankenlibc-abi --test time_abi_test vdso -- --nocapture
10 passed; 0 failed; 80 filtered out

cargo build -p frankenlibc-abi --release
passed with known pre-existing warnings
```
