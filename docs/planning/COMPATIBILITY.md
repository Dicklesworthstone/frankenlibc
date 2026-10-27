# FrankenLibC Compatibility Guide

> **Evidence source**: `tests/conformance/ld_preload_smoke_summary.v1.json`
>
> **Guide reconciled**: 2026-10-20. The recorded workload run is September 24, 2026 at `a8a4110b98606f26b296cd351d278073ee611ac9`; no new workload run is claimed by this documentation change.

FrankenLibC currently declares **L0 interposition over host glibc**. This guide describes the committed workload snapshot and its limitations. A historical pass does not establish that current HEAD or an arbitrary workload passes.

## Recorded Smoke Status — September 24, 2026

| Mode | Pass | Fail | Skip | Xfail |
|------|------|------|------|-------|
| **Strict** | 94 | 0 | 2 | 1 |
| **Hardened** | 95 | 0 | 2 | 0 |
| **Total** | 189 | 0 | 4 | 1 |

These mode assignments come from the artifact's structured fields. Its free-text notes instead assign the xfail to hardened `sed_substitute`; that disagreement remains unresolved in the artifact. The xfail and skips are not passes. The older June 3 table (60 passes / zero failures / four skips) covered a smaller battery and is superseded by this recorded corpus.

The 4 skips are the optional `redis-cli --version` and `nginx -v` probes (2 per mode), skipped only when those binaries are not installed. They are tracked separately from failures.

## Workloads Represented in the Recorded Corpus

The corpus includes the following workload families; consult the per-case transcripts for exact commands and outcomes:

- Coreutils (`ls`, `cat`, `echo`, `env`, `sort`, `wc`)
- `python3 -c` inline workloads
- `busybox uname -a`
- `sqlite3 :memory:`
- The integration link fixture (`tests/integration/link_test.c`)
- Repeated stress iterations of the above (5 iterations per stress case)
- GNU `FILE` constructors, `sed`, `grep`, `awk`, `find`, archive/compression round trips, `make`, Perl, Git, C++ runtime initialization, and Python extensions/subprocesses

## What Works (Hardened Mode)

The structured snapshot records 95 hardened-mode passes. Hardened mode can repair or deny invalid operations on explicitly wired paths; valid-program smoke cases do not establish universal memory safety. The smoke gate applies its per-run latency criterion, but this old result does not establish a current-source overhead bound.

## Known Issues

### Signature Guard Failures (0 cases in the checked run)

No signature-guard failures are recorded in the September 24 artifact. This is a statement about that run, not a new verification result.

### Performance Failures (0 cases in the checked run)

The September 24 artifact records zero `perf_failures` in both modes. Current allocator, hardened-sort and startup performance must be measured against a live incumbent in the same invocation; historical smoke timing does not discharge those tasks.

### Optional/Skipped Binaries

The following binaries are optional and skipped when not present (four of 194 cases in the recorded run):

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
