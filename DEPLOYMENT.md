# Deployment Guide

FrankenLibC currently ships as an interposition-first artifact, not as a full standalone replacement for glibc.

Current deployment status:

- Shipping artifact: `target/release/libfrankenlibc_abi.so`
- Current release claim: `L0` (`LD_PRELOAD` interpose on top of host glibc)
- Hardened interpose evidence exists, but the explicit `L1` claim is still blocked by claim-control gates in [`tests/conformance/replacement_levels.json`](/data/projects/frankenlibc/tests/conformance/replacement_levels.json)
- Planned standalone artifact: `libfrankenlibc_replace.so` is not shipped yet

Canonical source artifacts for deployment claims:

- [`tests/conformance/packaging_spec.json`](/data/projects/frankenlibc/tests/conformance/packaging_spec.json)
- [`tests/conformance/replacement_levels.json`](/data/projects/frankenlibc/tests/conformance/replacement_levels.json)
- [`tests/conformance/runtime_env_inventory.v1.json`](/data/projects/frankenlibc/tests/conformance/runtime_env_inventory.v1.json)
- [`tests/conformance/ld_preload_smoke_summary.v1.json`](/data/projects/frankenlibc/tests/conformance/ld_preload_smoke_summary.v1.json)

## Supported Deployment Model

What works today:

- Per-process interposition through `LD_PRELOAD`
- Strict mode interposition (`FRANKENLIBC_MODE` unset or `strict`)
- Hardened mode interposition (`FRANKENLIBC_MODE=hardened`)
- Gentoo validation lanes and Portage-hook-based preload workflows

What does not exist yet:

- No standalone `libc.so.6` replacement flow
- No curl installer
- No distro package
- No setuid/setgid preload support, because the loader ignores `LD_PRELOAD` there

## Prerequisites

- Linux host
- Nightly Rust toolchain
- `cc` available for integration fixtures and smoke checks
- `python3` for repo automation and E2E tooling
- Optional: `rch` if you want to offload the build

Toolchain bootstrap:

```bash
rustup toolchain install nightly
rustup override set nightly
```

## Build The Artifact

Local build:

```bash
cargo build -p frankenlibc-abi --release
```

Remote-offloaded build:

```bash
rch exec -- cargo build -p frankenlibc-abi --release
```

Expected output:

```bash
target/release/libfrankenlibc_abi.so
```

## Install Options

### Ephemeral repo-local run

```bash
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo hello
```

### Local user prefix

```bash
install -d "$HOME/.local/lib/frankenlibc"
install -m 755 target/release/libfrankenlibc_abi.so "$HOME/.local/lib/frankenlibc/"
LD_PRELOAD="$HOME/.local/lib/frankenlibc/libfrankenlibc_abi.so" /bin/echo hello
```

### System-style experimental prefix

```bash
sudo install -d /usr/lib/frankenlibc
sudo install -m 755 target/release/libfrankenlibc_abi.so /usr/lib/frankenlibc/
LD_PRELOAD=/usr/lib/frankenlibc/libfrankenlibc_abi.so /bin/echo hello
```

This is still interposition, not libc replacement. Do not repoint `/lib/.../libc.so.6` at FrankenLibC.

## Runtime Modes

`FRANKENLIBC_MODE` is process-wide and resolves once at startup.

| Env value | Resolved mode | Meaning |
|---|---|---|
| unset, `strict`, or anything unrecognized | `strict` | compatibility-first behavior, no repair rewrites |
| `hardened`, `repair`, `tsm`, `full` | `hardened` | repair/deny-capable membrane behavior |

Example strict run:

```bash
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/ls
```

Example hardened run:

```bash
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/ls
```

## Operator Configuration

Primary deployment-facing variables:

| Variable | Default | Purpose |
|---|---|---|
| `FRANKENLIBC_MODE` | `strict` | Selects strict vs hardened mode |
| `FRANKENLIBC_LOG` | unset | Structured runtime evidence log destination |
| `FRANKENLIBC_LIB` | auto-detected `target/release/libfrankenlibc_abi.so` | Tooling override for preload library path |
| `FRANKENLIBC_STARTUP_PHASE0` | `0` | Enables the phase-0 `__libc_start_main` startup path |
| `FRANKENLIBC_E2E_SEED` | `42` | Deterministic replay seed for E2E tooling |
| `FRANKENLIBC_E2E_STRESS_ITERS` | `5` | Stress-iteration control for E2E tooling |
| `FRANKENLIBC_EXTENDED_GATES` | `0` | Enables heavier CI and verification gates |
| `FRANKENLIBC_BENCH_PIN` | `0` | Benchmark-only CPU pinning control |

Gentoo / Portage-specific variables:

| Variable | Default | Purpose |
|---|---|---|
| `FRANKENLIBC_PORTAGE_ENABLE` | `1` | Global kill-switch for Gentoo hooks |
| `FRANKENLIBC_PHASE_ALLOWLIST` | `src_test pkg_test` | Limits which Portage phases activate preload |
| `FRANKENLIBC_PACKAGE_BLOCKLIST` | `sys-libs/glibc sys-apps/shadow` | Prevents preload injection for sensitive packages |
| `FRANKENLIBC_LOG_DIR` | `/var/log/frankenlibc/portage` | Root directory for hook-generated logs |
| `FRANKENLIBC_PORTAGE_LOG` | `/tmp/frankenlibc-portage-hooks.log` | Hook decision log path |
| `FRANKENLIBC_SKIP_STATIC` | `1` | Skips preload during static-only build phases |

For the exhaustive machine-generated inventory, use [`tests/conformance/runtime_env_inventory.v1.json`](/data/projects/frankenlibc/tests/conformance/runtime_env_inventory.v1.json).

Example shell setup:

```bash
export FRANKENLIBC_MODE=hardened
export FRANKENLIBC_LOG=/tmp/frankenlibc.jsonl
export FRANKENLIBC_LIB="$PWD/target/release/libfrankenlibc_abi.so"

LD_PRELOAD="$FRANKENLIBC_LIB" /bin/echo configured
```

## Verification Before You Trust A Deployment

Recommended gate order:

```bash
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/check_packaging.sh
bash scripts/check_replacement_levels.sh
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh
```

Useful supporting checks:

```bash
bash scripts/check_support_matrix_maintenance.sh
bash scripts/check_c_fixture_suite.sh
bash scripts/e2e_suite.sh smoke
```

Interpretation:

- `check_packaging.sh` validates the declared interpose/replace artifact contracts
- `check_replacement_levels.sh` validates the current maturity-level claim state
- `ld_preload_smoke.sh` runs real dynamic programs in strict and hardened modes
- `e2e_suite.sh` exercises broader replayable scenario packs

## Monitoring And Evidence

Runtime and deployment evidence lives in structured artifacts, not in prose alone.

Useful outputs:

- `FRANKENLIBC_LOG=/path/file.jsonl` for per-run structured runtime logs
- `target/ld_preload_smoke/<run_id>/` for smoke transcripts, traces, and ABI-compat reports
- `target/e2e_suite/<run_id>/` for E2E traces, pair reports, and flake-quarantine reports
- [`tests/conformance/reality_report.v1.json`](/data/projects/frankenlibc/tests/conformance/reality_report.v1.json) for current symbol-state reality
- [`tests/conformance/claim_reconciliation_report.v1.json`](/data/projects/frankenlibc/tests/conformance/claim_reconciliation_report.v1.json) for docs-vs-artifact claim consistency

## Gentoo Deployment And Operations

Gentoo validation is documented separately because it adds Portage hooks, runner configuration, and report generation beyond normal `LD_PRELOAD` use.

Start here:

- [`docs/gentoo/USER-GUIDE.md`](/data/projects/frankenlibc/docs/gentoo/USER-GUIDE.md)
- [`docs/gentoo/OPERATIONS.md`](/data/projects/frankenlibc/docs/gentoo/OPERATIONS.md)
- [`docs/gentoo/REFERENCE.md`](/data/projects/frankenlibc/docs/gentoo/REFERENCE.md)

## Troubleshooting

### `LD_PRELOAD` appears to do nothing

Verify the artifact exists and that the target process is dynamically linked:

```bash
test -f target/release/libfrankenlibc_abi.so
ldd /bin/echo
```

`LD_PRELOAD` will not affect static binaries or setuid/setgid binaries.

### Hardened mode is not emitting logs

Set the log path explicitly:

```bash
FRANKENLIBC_LOG=/tmp/franken.jsonl \
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo test
```

### The toolchain is wrong

This repo requires nightly:

```bash
rustup toolchain install nightly
rustup override set nightly
```

### The startup path breaks very early

The phase-0 startup path is still gated behind `FRANKENLIBC_STARTUP_PHASE0=1`. Leave it at the default `0` unless you are explicitly testing startup work.

### A deployment claim and a report disagree

Trust the generated artifacts, then rerun the relevant gate:

```bash
bash scripts/check_packaging.sh
bash scripts/check_replacement_levels.sh
bash scripts/check_claim_reconciliation.sh
```

## Security And Scope Boundaries

- The shipping deployment model still depends on host glibc
- FrankenLibC is not yet a blanket production-readiness claim for arbitrary workloads
- Hardened mode adds repair/deny behavior, but it does not turn unsafe applications into proven-safe programs
- The current green smoke battery is a real checked artifact, but it is still a curated battery
- Full standalone replacement remains planned work, not a completed deployment path
