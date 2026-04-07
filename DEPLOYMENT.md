# FrankenLibC Deployment Guide

This document describes how FrankenLibC is deployed today, what deployment modes are actually supported, and how to operate the current interpose-first artifact safely.

## Current Deployment Model

FrankenLibC is currently shipped as an interposition library, not as a full standalone libc replacement.

- Current artifact: `target/release/libfrankenlibc_abi.so`
- Current deployment style: `LD_PRELOAD`
- Current replacement-level claim: `L0` interpose
- Planned but not shipped: `libfrankenlibc_replace.so`

That distinction matters operationally. A clean classified symbol surface does not mean the project is already a drop-in standalone libc for arbitrary hosts and workloads.

## Prerequisites

### Host Requirements

- Linux host
- Rust nightly toolchain for local builds
- Cargo workspace build environment
- For Gentoo validation lanes: Docker plus Python 3.11+

### Architecture Status

- `x86_64` is the practical deployment target today.
- `aarch64` is an active bring-up area, not the default deployment story yet.

## Build And Artifact Paths

Build the preload artifact:

```bash
cargo build -p frankenlibc-abi --release
```

Produced library:

```bash
target/release/libfrankenlibc_abi.so
```

Optional verification before deployment:

```bash
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/check_support_matrix_maintenance.sh
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh
```

## Deployment Options

### Per-Process Interposition

This is the primary supported deployment path.

Strict mode:

```bash
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/ls
```

Hardened mode:

```bash
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/ls
```

### Local Prefix Install

Useful for repeatable operator experiments without touching system library paths.

```bash
install -d "$HOME/.local/lib/frankenlibc"
install -m 755 target/release/libfrankenlibc_abi.so "$HOME/.local/lib/frankenlibc/"
LD_PRELOAD="$HOME/.local/lib/frankenlibc/libfrankenlibc_abi.so" /bin/echo hello
```

### System-Style Install For Experiments

This is still an interpose deployment, not a system libc replacement.

```bash
sudo install -d /usr/lib/frankenlibc
sudo install -m 755 target/release/libfrankenlibc_abi.so /usr/lib/frankenlibc/
LD_PRELOAD=/usr/lib/frankenlibc/libfrankenlibc_abi.so /bin/echo hello
```

### Container Deployment

Current container-oriented deployment is centered on the Gentoo validation workflow rather than a generic production image.

```bash
docker build -f docker/gentoo/Dockerfile.frankenlibc -t frankenlibc/gentoo-frankenlibc:latest .
scripts/gentoo/fast-validate.sh --hardened
```

### What Does Not Exist Yet

- No packaged system-wide replacement libc install flow
- No supported static-link deployment path today
- No claim that arbitrary production workloads are ready for full replacement

## Runtime Configuration

The main runtime knob is `FRANKENLIBC_MODE`.

Example shell setup:

```bash
export FRANKENLIBC_MODE=hardened
export FRANKENLIBC_LOG=/tmp/franken.jsonl
export FRANKENLIBC_LIB="$PWD/target/release/libfrankenlibc_abi.so"

LD_PRELOAD="$FRANKENLIBC_LIB" /bin/echo configured
```

### Common Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `FRANKENLIBC_MODE` | `strict` | Process-wide immutable mode selection |
| `FRANKENLIBC_LOG` | unset | Structured runtime log path |
| `FRANKENLIBC_LIB` | unset | Tooling override for the built preload library |
| `FRANKENLIBC_EXTENDED_GATES` | `0` | Enables heavier CI and verification gates |
| `FRANKENLIBC_E2E_SEED` | `42` | Deterministic seed for E2E flows |
| `FRANKENLIBC_E2E_STRESS_ITERS` | `5` | Stress-iteration count for E2E scripts |
| `FRANKENLIBC_BENCH_PIN` | `0` | Benchmark-only CPU pinning control |
| `FRANKENLIBC_LOG_DIR` | `/var/log/frankenlibc/portage` | Gentoo hook log root |
| `FRANKENLIBC_LOG_FILE` | unset | Alias path exported into `FRANKENLIBC_LOG` |
| `FRANKENLIBC_PHASE_ALLOWLIST` | `src_test pkg_test` | Gentoo phase allowlist |
| `FRANKENLIBC_PACKAGE_BLOCKLIST` | `sys-libs/glibc sys-apps/shadow` | Gentoo package blocklist |
| `FRANKENLIBC_PORTAGE_ENABLE` | `1` | Gentoo Portage hook kill-switch |
| `FRANKENLIBC_PORTAGE_LOG` | `/tmp/frankenlibc-portage-hooks.log` | Gentoo hook decision log |
| `FRANKENLIBC_SKIP_STATIC` | `1` | Skip preload during static-library Gentoo builds |
| `FRANKENLIBC_STARTUP_PHASE0` | `0` | Startup gating knob for phase-0 `__libc_start_main` flow |
| `FRANKENLIBC_TMPDIR` | unset | Tooling temp-root override |

### Healing Policy Tuning

There is no stable public operator-facing per-action healing-tuning interface today. The practical deployment choices are:

- `strict` for compatibility-first behavior
- `hardened` for repair-or-deny behavior

Fine-grained healing policy remains defined by code and policy artifacts rather than a documented runtime control surface.

## Monitoring And Evidence

FrankenLibC favors structured artifacts over ad hoc operator intuition.

### Runtime And Verification Signals

- Structured runtime log: `FRANKENLIBC_LOG=/path/to/file.jsonl`
- Gentoo hook log: `FRANKENLIBC_PORTAGE_LOG`
- Gentoo log root: `FRANKENLIBC_LOG_DIR`
- Reality report: `/tmp/frankenlibc-reality.json` or chosen output path
- Membrane verification output: `/tmp/healing_oracle.json` or chosen output path

### Useful Verification Commands

```bash
cargo run -p frankenlibc-harness --bin harness -- reality-report \
  --support-matrix support_matrix.json \
  --output /tmp/frankenlibc-reality.json

cargo run -p frankenlibc-harness --bin harness -- verify-membrane \
  --mode both \
  --output /tmp/healing_oracle.json

bash scripts/check_support_matrix_maintenance.sh
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh
```

### Gentoo Monitoring Artifacts

- `artifacts/gentoo-builds/fast-validate/<timestamp>/summary.json`
- `data/gentoo/perf-results/perf_benchmark_results.v1.json`
- `data/gentoo/healing-analysis/summary.json`
- `data/gentoo/quarantine.json`

Dashboard generation:

```bash
python3 scripts/gentoo/validation_dashboard.py --format both --output artifacts/gentoo-dashboard.json
```

## Troubleshooting

### `LD_PRELOAD` Does Nothing

Check that the release library exists and that you are pointing to the right file:

```bash
test -f target/release/libfrankenlibc_abi.so
```

### Hardened Mode Appears Silent

Set an explicit runtime log path:

```bash
FRANKENLIBC_LOG=/tmp/franken.jsonl \
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo test
```

### Toolchain Mismatch

This repository uses nightly Rust:

```bash
rustup toolchain install nightly
rustup override set nightly
```

### Smoke Or Drift Gate Fails

Prefer the machine-generated artifacts over README prose. Start with:

```bash
bash scripts/check_support_matrix_maintenance.sh
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh
```

### Docker Daemon Unavailable For Gentoo Validation

- Start Docker and retry.
- If you only need pipeline wiring, run `scripts/gentoo/fast-validate.sh --dry-run`.

### Gentoo Hook Logs Missing

- Verify `FRANKENLIBC_LOG_DIR` and `FRANKENLIBC_PORTAGE_LOG` are writable.
- Re-run a minimal package and confirm JSONL emission.

### Unexpected Gentoo Package Skips

Check:

- `FRANKENLIBC_PHASE_ALLOWLIST`
- `FRANKENLIBC_PACKAGE_BLOCKLIST`
- `configs/gentoo/exclusions.json`

## Security Considerations

- `LD_PRELOAD`-based deployment does not apply to setuid/setgid binaries because the loader ignores `LD_PRELOAD` there.
- The shipping artifact is still interpose-first and still relies on the host deployment environment.
- Security claims are strongest at the libc boundary for supported ABI paths, not for arbitrary whole-program behavior.
- For the threat model, guarantees, healing actions, and formal safety claims, use [SECURITY.md](/data/projects/frankenlibc/SECURITY.md).

## Performance Tuning

### Mode Selection

- Use `strict` when you want compatibility-first behavior and minimal repair.
- Use `hardened` when you want repair-or-deny behavior and explicit evidence for suspicious inputs.

### Bench And Perf Gates

Benchmarking remains a verification activity, not a guarantee that every workload is already tuned:

```bash
cargo bench -p frankenlibc-bench
```

Perf-related environment knobs that exist today:

- `FRANKENLIBC_BENCH_PIN`
- `FRANKENLIBC_PERF_MAX_REGRESSION_PCT`
- `FRANKENLIBC_PERF_ALLOW_TARGET_VIOLATION`
- `FRANKENLIBC_PERF_SKIP_OVERLOADED`
- `FRANKENLIBC_PERF_ENABLE_KERNEL_SUITE`
- `FRANKENLIBC_PERF_MAX_LOAD_FACTOR`

### Quarantine And TLS Cache

Quarantine and TLS-cache behavior are part of the implementation and performance model, but there is not yet a documented stable operator-facing runtime tuning interface for them. Treat current quarantine depth and TLS-cache behavior as implementation details verified by benches and tests rather than deployment knobs.

## Gentoo Validation Operations

### Fast Lane

```bash
scripts/gentoo/fast-validate.sh --hardened
```

### Full Lane

```bash
python3 scripts/gentoo/build-runner.py --config configs/gentoo/build-config.toml
python3 scripts/gentoo/test-runner.py --package-file data/gentoo/build-order.txt
```

Limit to selected packages:

```bash
python3 scripts/gentoo/build-runner.py \
  --config configs/gentoo/build-config.toml \
  --package sys-apps/coreutils \
  --package net-misc/curl
```

### Documentation And Report Publishing

```bash
python3 scripts/gentoo/validate-docs.py --strict
python3 scripts/gentoo/generate-report.py \
  --franken-version 0.1.0 \
  --gentoo-stage3 2026-02-01 \
  --output docs/gentoo/VALIDATION-REPORT.md
```

### Preflight

```bash
python3 scripts/gentoo/validate-docs.py --strict
python3 scripts/gentoo/validate_cache.py --cache-dir /var/cache/binpkgs --strict
```

## Deployment Summary

If you need a practical deployment path today, use `libfrankenlibc_abi.so` through `LD_PRELOAD`, choose `strict` or `hardened` explicitly, run the smoke and maintenance gates, and treat Gentoo validation as the most developed containerized operations surface. Anything beyond that should be described as planned work, not shipped deployment capability.
