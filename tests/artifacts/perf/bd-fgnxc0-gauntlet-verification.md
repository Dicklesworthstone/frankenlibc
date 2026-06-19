# bd-fgnxc0 gauntlet verification

## Scope

- Bead: `bd-fgnxc0`
- Commit measured: `756f99657`
- Lever: TLS buffer reuse for wide printf format conversion.
- Workload: `swprintf(L"value=%d\n", 12345)` through FrankenLibC ABI versus
  host glibc `swprintf` on the same fixed wide format.
- Shared docs note: `docs/NEGATIVE_EVIDENCE.md`,
  `docs/RELEASE_READINESS_SCORECARD.md`, `.beads/issues.jsonl`, and the
  original `bd-fgnxc0` artifact were actively reserved by `BlackThrush` during
  this pass, so this bead-local artifact records the measured ledger and
  scorecard without editing those paths.

## Benchmark Evidence

Command:

```bash
AGENT_NAME=DarkRiver CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench stdio_glibc_baseline_bench -- \
  stdio_glibc_baseline_swprintf_wide_format --noplot
```

Environment:

- Worker: `vmi1149989`
- Tool: `criterion`
- Samples: 20 per implementation
- Artifact paths:
  - `/data/projects/.rch-targets/frankenlibc-cod-a/criterion/stdio_glibc_baseline_swprintf_wide_format/frankenlibc_abi/new/estimates.json`
  - `/data/projects/.rch-targets/frankenlibc-cod-a/criterion/stdio_glibc_baseline_swprintf_wide_format/host_glibc/new/estimates.json`

| Impl | Median ns/op | Mean ns/op | Median CI ns/op | Mean CI ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC ABI | 461.481 | 464.386 | 459.145..463.729 | 459.829..471.381 |
| host glibc | 4046.759 | 4075.679 | 3941.955..4139.416 | 3990.318..4169.777 |

Ratios:

- Median `frankenlibc / glibc`: `0.114037`
- Mean `frankenlibc / glibc`: `0.113941`
- Median speedup versus glibc: `8.769x`
- Mean speedup versus glibc: `8.776x`

## Negative-Evidence Ledger Entry

| Date | Lever / bead | Bench | FrankenLibC | glibc | Ratio | Verdict | Action |
| --- | --- | --- | ---: | ---: | ---: | --- | --- |
| 2026-06-19 | wide printf TLS format buffer pool (`bd-fgnxc0`) | `stdio_glibc_baseline_swprintf_wide_format` | 461.481 ns median | 4046.759 ns median | 0.114037 | WIN | Keep; no revert. Retry only if a same-worker rerun or wide printf differential suite shows regression. |

Dead-end update: no revert was needed. This pass did not retry allocator,
stdio-lock, bulk-I/O, `memchr_absent`, `log2f`, `malloc_free_256`, or `memcmp`
families.

## Conformance Guard

Focused command:

```bash
AGENT_NAME=DarkRiver CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo test -p frankenlibc-abi swprintf_formats --test wchar_abi_test
```

Result: passed on `hz2`, `2 passed; 0 failed; 123 filtered out`.

Non-counted check: `cargo test -p frankenlibc-abi pooled_wide_format --lib`
compiled but matched `0` tests, so it is not used as conformance evidence.

## Release-Readiness Scorecard

| Area | Status | Evidence |
| --- | --- | --- |
| Performance versus original glibc | PASS | FrankenLibC ABI median 461.481 ns versus glibc 4046.759 ns, ratio 0.114037. |
| Revert gate | PASS | Measured WIN; no source revert required. |
| Focused conformance | PASS | `swprintf_formats_integer` and `swprintf_formats_string` passed. |
| Evidence durability | PARTIAL | Bead-local artifact committed here; shared ledger/scorecard merge remains pending because those paths were reserved by `BlackThrush`. |
| Full release certification | PENDING | Full wide printf differential/fuzz suite and broad stdio bench matrix were not run in this focused pass. |

Verdict: keep `bd-fgnxc0` as a measured win for this workload.
