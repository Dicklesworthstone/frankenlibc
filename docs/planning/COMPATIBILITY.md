# FrankenLibC Compatibility Guide

> **Evidence source**: `tests/conformance/ld_preload_smoke_summary.v1.json`
>
> **Guide reconciled**: 2026-11-11. The committed workload run is November 11, 2026 (`run_id`: `20261111T134243Z-2744068`) at `44a61541664180227df61c46d491ef024d2b4536`.

FrankenLibC currently declares **L0 interposition over host glibc**. This guide describes the committed workload snapshot and its limitations. A recorded pass on the curated battery does not establish that an arbitrary later commit or unqualified workload passes.

## Recorded Smoke Status — November 11, 2026

| Mode | Pass | Fail | Skip | Xfail |
|------|------|------|------|-------|
| **Strict** | 175 | 0 | 2 | 0 |
| **Hardened** | 173 | 0 | 2 | 0 |
| **Total** | 348 | 0 | 4 | 0 |

These mode assignments come from `tests/conformance/ld_preload_smoke_summary.v1.json` (`run_id`: `20261111T134243Z-2744068`, source commit `44a61541…`). Historical snapshots (June 3 and September 24) covered smaller batteries and are superseded by this recorded corpus.

The 4 skips are the optional `redis-cli --version` and `nginx -v` probes (2 per mode), skipped only when those binaries are not installed. They are tracked separately from failures.

## Workloads Represented in the Recorded Corpus

The corpus includes the following workload families; consult the per-case transcripts for exact commands and outcomes:

- Coreutils (`ls`, `cat`, `echo`, `env`, `sort`, `wc`)
- `python3 -c` inline workloads
- `busybox uname -a`
- `sqlite3 :memory:`
- The integration link fixture (`tests/integration/link_test.c`)
- Repeated stress iterations of the above (5 iterations per stress case)
- GNU `FILE` constructors, `sed`, `grep`, `awk`, `find`, archive/compression round trips, `make`, Perl, Git, C++ runtime initialization, Python extensions/subprocesses, `RLIMIT_DATA=10MB` VM-geometry probes, and warm-`TLS_CACHE` canary corruption probes

## What Works (Hardened Mode)

The structured snapshot records 173 hardened-mode passes (`0` failures, `2` optional skips, `0` xfails). Hardened mode can repair or deny invalid operations on explicitly wired paths; valid-program smoke cases do not establish universal memory safety.

## Known Issues

### Signature Guard Failures (0 cases in the checked run)

No signature-guard failures are recorded in the November 11 artifact (`20261111T134243Z-2744068`). This is a statement about that run, not a blanket guarantee for unverified commits.

### Performance Failures (0 cases in the checked run)

The November 11 artifact records zero `perf_failures` in both modes (`deployed_overhead_passed: true`). Workload-specific allocator, hardened-sort and startup performance must still be measured against a live incumbent in the same invocation when evaluating new workloads.

### Optional/Skipped Binaries

The following binaries are optional and skipped when not present (four of 352 cases in the recorded run):

- `redis-cli` (network service)
- `nginx` (web server)

## Maturity Level

The canonical `tests/conformance/replacement_levels.json` declares **L0**:

- **L0 (Current)**: Interposition over host glibc with native, host-backed and unsupported subsets explicitly tracked
- L1 (Promotion target): Hardened interposition satisfying zero-stub, workload and performance requirements; host glibc remains required
- L2 (Future): Standalone-ready qualification
- L3 (Future): Standalone replacement artifact

## Decision Tree

Use this decision tree to determine if FrankenLibC fits your workload:

```
Is your workload single-threaded?
├── Yes → Likely works in strict mode
└── No → Does it use complex pthread patterns?
    ├── Yes → May have issues; test thoroughly
    └── No → Likely works in strict mode

Do you need hardened mode security checks?
├── Yes → Check that the required paths are wired; measure workload-specific overhead
└── No → Use strict mode for better performance

Is your workload latency-sensitive?
├── Yes → Test carefully; may have perf regressions
└── No → Should work if passing smoke battery
```

This tree is heuristics from the curated battery, not a guarantee for arbitrary workloads; untested workloads need their own smoke run (`scripts/ld_preload_smoke.sh`).

## Testing Your Workload

Run with FrankenLibC interposition:

```bash
# Strict mode
LD_PRELOAD=/path/to/libfrankenlibc_abi.so your_program

# Hardened mode
FRANKENLIBC_MODE=hardened LD_PRELOAD=/path/to/libfrankenlibc_abi.so your_program
```

Check the exit status and verify expected behavior.

## Evidence Artifacts

Use these evidence artifacts with their recorded source and build identities; updating this guide does not regenerate execution evidence:

- Smoke battery: `tests/conformance/ld_preload_smoke_summary.v1.json`
- Performance data: `tests/conformance/heavyweight_runtime_perf.v1.json`
- Smoke index: `tests/conformance/ld_preload_smoke_e2e_index.v1.json`
