# FrankenLibC Compatibility Guide

> **Generated from**: `tests/conformance/ld_preload_smoke_summary.v1.json`  
> **Last regeneration**: 2026-05-22 (bd-as0w2.6)

This guide states which workloads work today under `LD_PRELOAD`, which are degraded, and which are broken, per strict and hardened mode.

## Current Status

| Mode | Pass | Fail | Skip | Status |
|------|------|------|------|--------|
| **Strict** | 22 | 8 | 2 | RED |
| **Hardened** | 18 | 12 | 2 | RED |
| **Total** | 40 | 20 | 4 | RED |

## What Works Today (Strict Mode)

Workloads that pass the curated smoke battery in strict mode:

- Basic command-line utilities (`echo`, `cat`, `ls`, `grep`, `sort`, `head`, `tail`)
- Standard file operations (`cp`, `mv`, `rm`, `mkdir`)
- Simple shell scripts and pipelines
- Most single-threaded applications
- Applications using basic string/memory operations

## What Works (Hardened Mode)

Hardened mode adds additional runtime checks. Passing workloads in hardened mode:

- Same as strict mode, minus some latency-sensitive applications
- Applications that can tolerate ~2x latency overhead

## Known Issues

### Signature Guard Failures (12 cases)

Some applications trigger signature guard checks that cause startup failures. This typically happens with:

- Applications using unusual calling conventions
- Dynamically generated code that doesn't follow ABI conventions
- Some JIT-compiled runtimes

### Performance Failures (8 cases)

Applications failing due to performance regression (exceeding 2x baseline latency):

- High-frequency system call workloads
- Real-time or latency-sensitive applications
- Some database benchmarks

### Optional/Skipped Binaries

The following binaries are optional and skipped when not present:

- `redis-cli` (network service)
- `nginx` (web server)

## Maturity Level

FrankenLibC is currently at **L1 interpose** maturity:

- L0 (In-progress): Basic compilation and symbol resolution
- **L1 (Current)**: LD_PRELOAD interposition works for many workloads
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
├── Yes → Expect ~2x latency overhead
└── No → Use strict mode for better performance

Is your workload latency-sensitive?
├── Yes → Test carefully; may have perf regressions
└── No → Should work if passing smoke battery
```

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
