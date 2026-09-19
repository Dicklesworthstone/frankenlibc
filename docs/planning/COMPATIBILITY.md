# FrankenLibC Compatibility Guide

> **Generated from**: `tests/conformance/ld_preload_smoke_summary.v1.json`  
> **Last regeneration**: 2026-09-18 (bd-reality-202609-lx578q.10; supersedes the 2026-05-22 table that recorded 40/20/4 RED)

This guide states which workloads work today under `LD_PRELOAD`, which are degraded, and which are broken, per strict and hardened mode. Every number below is copied from the checked-in smoke artifact (run `SnowyMill-ldfix-20260603T034530Z`, checked June 3, 2026); it is a curated workload signal, not a broad production-readiness claim.

## Current Status

| Mode | Pass | Fail | Skip | Status |
|------|------|------|------|--------|
| **Strict** | 30 | 0 | 2 | GREEN |
| **Hardened** | 30 | 0 | 2 | GREEN |
| **Total** | 60 | 0 | 4 | GREEN |

The 4 skips are the optional `redis-cli --version` and `nginx -v` probes (2 per mode), skipped only when those binaries are not installed. They are tracked separately from failures.

## What Works Today (Strict Mode)

Workloads that pass the curated smoke battery in strict mode:

- Coreutils (`ls`, `cat`, `echo`, `env`, `sort`, `wc`)
- `python3 -c` inline workloads
- `busybox uname -a`
- `sqlite3 :memory:`
- The integration link fixture (`tests/integration/link_test.c`)
- Repeated stress iterations of the above (5 iterations per stress case)

## What Works (Hardened Mode)

`FRANKENLIBC_MODE=hardened` passes the same 30-case battery. Hardened mode adds deterministic repair for invalid patterns; the smoke gate also enforces the ~2x latency bound for this battery in both modes.

## Known Issues

### Signature Guard Failures (0 cases in the checked run)

No signature-guard failures occurred in the checked June 3, 2026 battery. An earlier 2026-05-22 generation of this guide recorded 12 such failures from an older run; that state is superseded.

### Performance Failures (0 cases in the checked run)

No performance-gate failures occurred in the checked battery (0 `perf_failures` in both modes). The ~2x latency bound is enforced per-run by the smoke gate rather than assumed.

### Optional/Skipped Binaries

The following binaries are optional and skipped when not present (4 of 64 cases in the checked run):

- `redis-cli` (network service)
- `nginx` (web server)

## Maturity Level

FrankenLibC is currently at **L1 interpose** maturity per `tests/conformance/replacement_levels.json`:

- L0 (In-progress): Basic compilation and symbol resolution
- **L1 (Current)**: LD_PRELOAD interposition works for the curated smoke battery in both modes
- L2 (Future): Standalone replacement (no host glibc)
- L3 (Future): Full glibc replacement artifact

## Decision Tree

Use this decision tree to determine if FrankenLibC fits your workload:

```
Is your workload single-threaded?
├── Yes → Likely works in strict mode
└── No → Does it use complex pthread patterns?
    ├── Yes → May have issues; test thoroughly
    └── No → Likely works in strict mode

Do you need hardened mode security checks?
├── Yes → Expect up to ~2x latency overhead (enforced bound for this battery)
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

This guide is regenerated from machine artifacts:

- Smoke battery: `tests/conformance/ld_preload_smoke_summary.v1.json`
- Performance data: `tests/conformance/heavyweight_runtime_perf.v1.json`
- Smoke index: `tests/conformance/ld_preload_smoke_e2e_index.v1.json`
